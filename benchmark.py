#!/usr/bin/env python3

import itertools
import os
import signal
import statistics
import subprocess
import time


def run_cmd(cmd, capture_output=True, check=True):
	s = subprocess.PIPE if capture_output else subprocess.DEVNULL
	return subprocess.run(cmd, universal_newlines=True, stdout=s, stderr=s)

def start_cmd(cmd, capture_output=True):
	s = subprocess.PIPE if capture_output else subprocess.DEVNULL
	return subprocess.Popen(cmd, universal_newlines=True, stdout=s, stderr=s)

def wait_cmd(process, check=True):
	out, err = process.communicate()
	ret = process.poll()
	if check and ret:
		raise subprocess.CalledProcessError(ret, process.args, out, err)
	return subprocess.CompletedProcess(process.args, ret, out, err)

def stop_cmd(process, check=True):
	process.send_signal(signal.SIGINT)
	return wait_cmd(process, check=check)


server_host = "meli-20"
ssh_user = "alexey"

def server_cmd(cmd):
	return ["ssh", "-i", "/home/{}/.ssh/id_rsa".format(ssh_user), "{}@{}".format(ssh_user, server_host)] + cmd


interval = 100

def start_blktrace_server(out_dir, use_rdma):
	run_cmd(server_cmd(["mkdir", "-p", out_dir]))
	p = start_cmd(server_cmd(["rblktrace", "-D", out_dir, "-l"] + (["-R", "-i", str(interval)] if use_rdma else [])))
	time.sleep(0.2)
	return p

def stop_blktrace_server(process):
	run_cmd(server_cmd(["killall", "-SIGINT", "rblktrace"]))
	return wait_cmd(process)


def blktrace_dev_args(devices):
	return list(itertools.chain.from_iterable(("-d", d) for d in devices))

def start_blktrace_client(devices, use_rdma):
	p = start_cmd(["rblktrace", "-h", server_host, "-R" if use_rdma else "-s"] + blktrace_dev_args(devices))
	time.sleep(0.2)
	return p

def start_local_blktrace(devices, out_dir):
	p = start_cmd(["rblktrace", "-D", out_dir] + blktrace_dev_args(devices))
	time.sleep(0.1)
	return p


def get_cpu_usage(process):
	return float(run_cmd(["ps", "-p", "{}".format(process.pid), "-o", r"%cpu"]).stdout.splitlines()[-1].strip())

def get_server_cpu_usage():
	return float(run_cmd(server_cmd(["ps", "-C", "rblktrace", "-o", r"%cpu"])).stdout.splitlines()[-1].strip())


def get_local_trace_size(out_dir):
	return int(run_cmd(["du", "-b", "-s", out_dir]).stdout.split()[0])

def get_server_trace_size(out_dir):
	return int(run_cmd(server_cmd(["du", "-b", "-s", out_dir])).stdout.split()[0])


def discard_local_trace(out_dir):
	run_cmd(["rm", "-rf", out_dir])

def discard_server_trace(out_dir):
	run_cmd(server_cmd(["rm", "-rf", out_dir]))


def init_fs(device, fs, mnt_dir):
	run_cmd(["umount", "-l", device], check=False)
	run_cmd(["mkfs.{}".format(fs), device])
	run_cmd(["mount", device, mnt_dir])


def get_max_online_cpu():
	with open("/sys/devices/system/cpu/online", "r") as f:
		return int(f.read().strip().split(",")[-1].split("-")[-1])

def get_online_cpu_count():
	with open("/sys/devices/system/cpu/online", "r") as f:
		ranges = f.read().strip().split(",")
		n = len(ranges)
		for r in ranges:
			if "-" in r:
				start, end = r.split("-")
				n += int(end) - int(start)
		return n

def is_cpu_online(cpu):
	with open("/sys/devices/system/cpu/cpu{}/online".format(cpu), "r") as f:
		return f.read().strip() == "1"

def set_cpu_online(cpu, online):
	with open("/sys/devices/system/cpu/cpu{}/online".format(cpu), "w") as f:
		f.write("1" if online else "0")

# Returns the list of disabled CPU IDs
def disable_extra_cpus(active_cpus):
	n = get_online_cpu_count()
	if active_cpus > n:
		raise ValueError("Not enough CPUs: {} > {}".format(active_cpus, n))
	disabled = []
	for cpu in reversed(range(get_max_online_cpu() + 1)):
		if n == active_cpus: break
		if is_cpu_online(cpu):
			set_cpu_online(cpu, False)
			disabled.append(cpu)
			n -= 1
	return disabled


def enable_extra_cpus(disabled):
	for cpu in disabled:
		set_cpu_online(cpu, True)


def fio_cmd(fio_dir, workload, io_size, file_size, jobs, runtime=None):
	return ["fio", "--name=test", "--ioengine=psync", "--direct=1", "--thread", "--directory={}".format(fio_dir),
	        "--rw={}".format(workload), "--bs={}".format(io_size), "--size={}".format(file_size),
	        "--numjobs={}".format(jobs), "--runtime={}".format(runtime), "--time_based"]

def start_create_fio_files(fio_dir, size, count):
	return start_cmd(fio_cmd(fio_dir, "read", "1m", size, count, 1))

def start_cpu_load(load, jobs):
	return start_cmd(["fio", "--name=cpu", "--ioengine=cpuio", "--cpuload={}".format(load),
	                  "--thread", "--numjobs={}".format(jobs)], capture_output=False)

def run_fio(fio_dirs, workload, io_size, file_size, jobs, runtime):
	processes = [start_cmd(fio_cmd(d, workload, io_size, file_size, jobs, runtime)) for d in fio_dirs]
	return [wait_cmd(p) for p in processes]

def parse_fio_througput(output):
	s = output.split("aggrb=")[1].split(",")[0]
	if "KB/s" in s:
		return float(s.split("KB/s")[0])
	if 'MB/s' in s:
		return float(s.split("MB/s")[0]) * 1024
	raise Exception("Unknown throughput format: {}".format(s))


def run_workload(active_cpus, mnt_dirs, do_cpu_load, workload, io_size, file_size, jobs, runtime):
	cpu_load_process = start_cpu_load(100, active_cpus) if do_cpu_load else None
	completed_fios = run_fio(mnt_dirs, workload, io_size, file_size, jobs, runtime)
	cpu_load_usage = get_cpu_usage(cpu_load_process) if do_cpu_load else 0.0
	if do_cpu_load: stop_cmd(cpu_load_process, check=False)
	return completed_fios, cpu_load_usage

def get_workload_result(result_dir, completed_fios):
	for i in range(len(completed_fios)):
		with open("{}/fio_{}.out".format(result_dir, i), "w") as f:
			f.write(completed_fios[i].stdout)
	return sum(parse_fio_througput(c.stdout) for c in completed_fios)

def output_result(result_dir, fio_throughput, client_cpu_usage, server_cpu_usage, trace_size, cpu_load_usage):
	with open("{}/result.out".format(result_dir), "w") as f:
		f.write("fio_throughput = {} KB/s\n".format(fio_throughput))
		f.write("client_cpu_usage = {}%\n".format(client_cpu_usage))
		f.write("server_cpu_usage = {}%\n".format(server_cpu_usage))
		f.write("trace_size = {}\n".format(trace_size))
		f.write("cpu_load_usage = {}%\n".format(cpu_load_usage))


def run_without_tracing(result_dir, active_cpus, mnt_dirs, do_cpu_load, workload, io_size, file_size, jobs, runtime):
	disabled_cpus = disable_extra_cpus(active_cpus)	
	try:
		completed_fios, cpu_load_usage = run_workload(active_cpus, mnt_dirs, do_cpu_load, workload,
		                                              io_size, file_size, jobs, runtime)
	finally:
		enable_extra_cpus(disabled_cpus)

	fio_throughput = get_workload_result(result_dir, completed_fios)
	output_result(result_dir, fio_throughput, 0.0, 0.0, 0, cpu_load_usage)


def run_with_tracing(result_dir, active_cpus, devices, mnt_dirs, remote, out_dir,
                     use_rdma, do_cpu_load, workload, io_size, file_size, jobs, runtime):
	disabled_cpus = disable_extra_cpus(active_cpus)
	try:
		server_process = start_blktrace_server(out_dir, use_rdma) if remote else None
		client_process = start_blktrace_client(devices, use_rdma) if remote else None
		tracers = None if remote else [start_local_blktrace([devices[i]], "{}/trace".format(mnt_dirs[i]))
                                       for i in range(len(devices))]

		completed_fios, cpu_load_usage = run_workload(active_cpus, mnt_dirs, do_cpu_load, workload,
		                                              io_size, file_size, jobs, runtime)

		client_cpu_usage = get_cpu_usage(client_process) if remote else sum(get_cpu_usage(t) for t in tracers)
		server_cpu_usage = get_server_cpu_usage() if remote else 0.0
		completed_client = stop_cmd(client_process) if remote else None
		completed_server = stop_blktrace_server(server_process) if remote else None
		completed_tracers = None if remote else [stop_cmd(t) for t in tracers]

	finally:
		enable_extra_cpus(disabled_cpus)

	trace_size = get_server_trace_size(out_dir) if remote else sum(get_local_trace_size("{}/trace".format(mnt_dirs[i]))
	                                                               for i in range(len(devices)))
	if remote:
		discard_server_trace(out_dir)
	else:
		for i in range(len(devices)):
			discard_local_trace("{}/trace".format(mnt_dirs[i]))

	fio_throughput = get_workload_result(result_dir, completed_fios)

	if remote:
		with open("{}/client.out".format(result_dir), "w") as f:
			f.write(completed_client.stdout)
		with open("{}/server.out".format(result_dir), "w") as f:
			f.write(completed_server.stdout)
	else:
		for i in range(len(devices)):
			with open("{}/tracer_{}.out".format(result_dir, i), "w") as f:
				f.write(completed_tracers[i].stdout)

	output_result(result_dir, fio_throughput, client_cpu_usage, server_cpu_usage, trace_size, cpu_load_usage)


def run_single_experiment(result_dir, runs, active_cpus, devices, fs, mnt_dirs, do_tracing, remote,
                          out_dir, use_rdma, do_cpu_load, workload, io_size, file_size, jobs, runtime):
	for i in range(runs):
		for j in range(len(devices)):
			print("initializing fs {}/{} ...".format(j + 1, len(devices)))
			init_fs(devices[j], fs, mnt_dirs[j])

		if "read" in workload:
			print("creating fio files ...")
			processes = [start_create_fio_files(d, file_size, jobs) for d in mnt_dirs]
			for p in processes:
				wait_cmd(p)

		result_subdir = "{}/run{}".format(result_dir, i)
		run_cmd(["mkdir", "-p", result_subdir])
		print("run {}/{} ...".format(i + 1, runs))

		if do_tracing:
			run_with_tracing(result_subdir, active_cpus, devices, mnt_dirs, remote, out_dir,
			                 use_rdma, do_cpu_load, workload, io_size, file_size, jobs, runtime)
		else:
			run_without_tracing(result_subdir, active_cpus, mnt_dirs, do_cpu_load,
			                    workload, io_size, file_size, jobs, runtime)

	print("done")


def run_full_experiment(name, runs, active_cpus, devices, fs, mnt_dirs, out_dir,
                        do_cpu_load, workload, io_size, file_size, jobs, runtime):
	print("running without tracing ...")
	run_single_experiment("results/{}/none".format(name), runs, active_cpus, devices, fs, mnt_dirs, False,
	                      None, None, None, do_cpu_load, workload, io_size, file_size, jobs, runtime)

	print("running with local tracing ...")
	run_single_experiment("results/{}/local".format(name), runs, active_cpus, devices, fs, mnt_dirs, True,
	                      False, None, None, do_cpu_load, workload, io_size, file_size, jobs, runtime)

	print("running with tcp tracing ...")
	run_single_experiment("results/{}/tcp".format(name), runs, active_cpus, devices, fs, mnt_dirs, True,
	                      True, out_dir, False, do_cpu_load, workload, io_size, file_size, jobs, runtime)

	print("running with rdma tracing ...")
	run_single_experiment("results/{}/rdma".format(name), runs, active_cpus, devices, fs, mnt_dirs, True,
	                      True, out_dir, True, do_cpu_load, workload, io_size, file_size, jobs, runtime)


experiments = [
	dict(
		name="ramdisk_ext4_randread",
		runs=5,
		active_cpus=28,
		devices=["/dev/ram0"],
		fs="ext4",
		mnt_dirs=["/mnt/ramdisk"],
		out_dir="/dev/shm",
		do_cpu_load=False,
		workload="randread",
		io_size=512,
		file_size="2g",
		jobs=28,
		runtime=30
	),
	dict(
		name="ramdisk_ext4_seqwrite",
		runs=5,
		active_cpus=28,
		devices=["/dev/ram0"],
		fs="ext4",
		mnt_dirs=["/mnt/ramdisk"],
		out_dir="/dev/shm",
		do_cpu_load=False,
		workload="write",
		io_size=512,
		file_size="2g",
		jobs=28,
		runtime=30
	),

	dict(
		name="nvme_ext4_seqread_512",
		runs=5,
		active_cpus=28,
		devices=["/dev/nvme0n1p1", "/dev/nvme1n1p1", "/dev/nvme2n1p1"],
		fs="ext4",
		mnt_dirs=["/mnt/nvme0", "/mnt/nvme1", "/mnt/nvme2"],
		out_dir="/scratch/trace",
		do_cpu_load=False,
		workload="read",
		io_size=512,
		file_size="8g",
		jobs=8,
		runtime=60
	),
	dict(
		name="nvme_ext4_seqread_4k",
		runs=5,
		active_cpus=28,
		devices=["/dev/nvme0n1p1", "/dev/nvme1n1p1", "/dev/nvme2n1p1"],
		fs="ext4",
		mnt_dirs=["/mnt/nvme0", "/mnt/nvme1", "/mnt/nvme2"],
		out_dir="/scratch/trace",
		do_cpu_load=False,
		workload="read",
		io_size="4k",
		file_size="8g",
		jobs=8,
		runtime=60
	),
	dict(
		name="nvme_ext4_seqread_64k",
		runs=5,
		active_cpus=28,
		devices=["/dev/nvme0n1p1", "/dev/nvme1n1p1", "/dev/nvme2n1p1"],
		fs="ext4",
		mnt_dirs=["/mnt/nvme0", "/mnt/nvme1", "/mnt/nvme2"],
		out_dir="/scratch/trace",
		do_cpu_load=False,
		workload="read",
		io_size="64k",
		file_size="8g",
		jobs=8,
		runtime=60
	),

	dict(
		name="nvme_ext4_seqwrite",
		runs=5,
		active_cpus=28,
		devices=["/dev/nvme0n1p1", "/dev/nvme1n1p1", "/dev/nvme2n1p1"],
		fs="ext4",
		mnt_dirs=["/mnt/nvme0", "/mnt/nvme1", "/mnt/nvme2"],
		out_dir="/scratch/trace",
		do_cpu_load=False,
		workload="write",
		io_size=512,
		file_size="8g",
		jobs=16,
		runtime=60
	),
	dict(
		name="nvme_ext4_seqwrite_cpubound",
		runs=5,
		active_cpus=28,
		devices=["/dev/nvme0n1p1", "/dev/nvme1n1p1", "/dev/nvme2n1p1"],
		fs="ext4",
		mnt_dirs=["/mnt/nvme0", "/mnt/nvme1", "/mnt/nvme2"],
		out_dir="/scratch/trace",
		do_cpu_load=True,
		workload="write",
		io_size=512,
		file_size="8g",
		jobs=16,
		runtime=60
	),

	dict(
		name="nvme_ext4_randread",
		runs=5,
		active_cpus=28,
		devices=["/dev/nvme0n1p1", "/dev/nvme1n1p1", "/dev/nvme2n1p1"],
		fs="ext4",
		mnt_dirs=["/mnt/nvme0", "/mnt/nvme1", "/mnt/nvme2"],
		out_dir="/scratch/trace",
		do_cpu_load=False,
		workload="randread",
		io_size=512,
		file_size="8g",
		jobs=16,
		runtime=60
	),
	dict(
		name="nvme_ext4_randread_cpubound",
		runs=5,
		active_cpus=28,
		devices=["/dev/nvme0n1p1", "/dev/nvme1n1p1", "/dev/nvme2n1p1"],
		fs="ext4",
		mnt_dirs=["/mnt/nvme0", "/mnt/nvme1", "/mnt/nvme2"],
		out_dir="/scratch/trace",
		do_cpu_load=True,
		workload="randread",
		io_size=512,
		file_size="8g",
		jobs=16,
		runtime=60
	),

	#...
]


def main():
	for i in range(len(experiments)):
		print("experiment {}/{}: {} ...".format(i + 1, len(experiments), experiments[i]["name"]))
		run_full_experiment(**experiments[i])

if __name__ == '__main__':
	main()
