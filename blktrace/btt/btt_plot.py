#! /usr/bin/env python
#
# btt_plot.py: Generate matplotlib plots for BTT generate data files
#
#  (C) Copyright 2009 Hewlett-Packard Development Company, L.P.
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

"""
btt_plot.py: Generate matplotlib plots for BTT generated data files

Files handled:
  AQD	- Average Queue Depth		Running average of queue depths

  BNOS	- Block numbers accessed	Markers for each block

  Q2D	- Queue to Issue latencies	Running averages
  D2C	- Issue to Complete latencies	Running averages
  Q2C	- Queue to Complete latencies	Running averages

Usage:
  btt_plot_aqd.py	equivalent to: btt_plot.py -t aqd	<type>=aqd
  btt_plot_bnos.py	equivalent to: btt_plot.py -t bnos	<type>=bnos
  btt_plot_q2d.py	equivalent to: btt_plot.py -t q2d	<type>=q2d
  btt_plot_d2c.py	equivalent to: btt_plot.py -t d2c	<type>=d2c
  btt_plot_q2c.py	equivalent to: btt_plot.py -t q2c	<type>=q2c

Arguments:
  [ -A          | --generate-all   ] Default: False
  [ -L          | --no-legend      ] Default: Legend table produced
  [ -o <file>   | --output=<file>  ] Default: <type>.png
  [ -T <string> | --title=<string> ] Default: Based upon <type>
  [ -v          | --verbose        ] Default: False
  <data-files...>

  The -A (--generate-all) argument is different: when this is specified,
  an attempt is made to generate default plots for all 5 types (aqd, bnos,
  q2d, d2c and q2c). It will find files with the appropriate suffix for
  each type ('aqd.dat' for example). If such files are found, a plot for
  that type will be made. The output file name will be the default for
  each type. The -L (--no-legend) option will be obeyed for all plots,
  but the -o (--output) and -T (--title) options will be ignored.
"""

from __future__ import absolute_import
from __future__ import print_function
import six
from six.moves import range
__author__ = 'Alan D. Brunelle <alan.brunelle@hp.com>'

#------------------------------------------------------------------------------

import matplotlib
matplotlib.use('Agg')
import getopt, glob, os, sys
import matplotlib.pyplot as plt

plot_size	= [10.9, 8.4]	# inches...

add_legend	= True
generate_all	= False
output_file	= None
title_str	= None
type		= None
verbose		= False

types		= [ 'aqd', 'q2d', 'd2c', 'q2c', 'live', 'bnos' ]
progs		= [ 'btt_plot_%s.py' % t for t in types ]

get_base 	= lambda file: file[file.find('_')+1:file.rfind('_')]

#------------------------------------------------------------------------------
def fatal(msg):
	"""Generate fatal error message and exit"""

	print('FATAL: %s' % msg, file=sys.stderr)
	sys.exit(1)

#------------------------------------------------------------------------------
def gen_legends(ax, legends):
	leg = ax.legend(legends, 'best', shadow=True)
	frame = leg.get_frame()
	frame.set_facecolor('0.80')
	for t in leg.get_texts():
		t.set_fontsize('xx-small')

#----------------------------------------------------------------------
def get_data(files):
	"""Retrieve data from files provided.

	Returns a database containing:
		'min_x', 'max_x' 	- Minimum and maximum X values found
		'min_y', 'max_y' 	- Minimum and maximum Y values found
		'x', 'y'		- X & Y value arrays
		'ax', 'ay'		- Running average over X & Y --
					  if > 10 values provided...
	"""
	#--------------------------------------------------------------
	def check(mn, mx, v):
		"""Returns new min, max, and float value for those passed in"""

		v = float(v)
		if mn == None or v < mn: mn = v
		if mx == None or v > mx: mx = v
		return mn, mx, v

	#--------------------------------------------------------------
	def avg(xs, ys):
		"""Computes running average for Xs and Ys"""

		#------------------------------------------------------
		def _avg(vals):
			"""Computes average for array of values passed"""

			total = 0.0
			for val in vals:
				total += val
			return total / len(vals)

		#------------------------------------------------------
		if len(xs) < 1000:
			return xs, ys

		axs = [xs[0]]
		ays = [ys[0]]
		_xs = [xs[0]]
		_ys = [ys[0]]

		x_range = (xs[-1] - xs[0]) / 100
		for idx in range(1, len(ys)):
			if (xs[idx] - _xs[0]) > x_range:
				axs.append(_avg(_xs))
				ays.append(_avg(_ys))
				del _xs, _ys

				_xs = [xs[idx]]
				_ys = [ys[idx]]
			else:
				_xs.append(xs[idx])
				_ys.append(ys[idx])

		if len(_xs) > 1:
			axs.append(_avg(_xs))
			ays.append(_avg(_ys))

		return axs, ays

	#--------------------------------------------------------------
	global verbose

	db = {}
	min_x = max_x = min_y = max_y = None
	for file in files:
		if not os.path.exists(file):
			fatal('%s not found' % file)
		elif verbose:
			print('Processing %s' % file)

		xs = []
		ys = []
		for line in open(file, 'r'):
			f = line.rstrip().split(None)
			if line.find('#') == 0 or len(f) < 2:
				continue
			(min_x, max_x, x) = check(min_x, max_x, f[0])
			(min_y, max_y, y) = check(min_y, max_y, f[1])
			xs.append(x)
			ys.append(y)

		db[file] = {'x':xs, 'y':ys}
		if len(xs) > 10:
			db[file]['ax'], db[file]['ay'] = avg(xs, ys)
		else:
			db[file]['ax'] = db[file]['ay'] = None

	db['min_x'] = min_x
	db['max_x'] = max_x
	db['min_y'] = min_y
	db['max_y'] = max_y
	return db

#----------------------------------------------------------------------
def parse_args(args):
	"""Parse command line arguments.

	Returns list of (data) files that need to be processed -- /unless/
	the -A (--generate-all) option is passed, in which case superfluous
	data files are ignored...
	"""

	global add_legend, output_file, title_str, type, verbose
	global generate_all

	prog = args[0][args[0].rfind('/')+1:]
	if prog == 'btt_plot.py':
		pass
	elif not prog in progs:
		fatal('%s not a valid command name' % prog)
	else:
		type = prog[prog.rfind('_')+1:prog.rfind('.py')]

	s_opts = 'ALo:t:T:v'
	l_opts = [ 'generate-all', 'type', 'no-legend', 'output', 'title',
		   'verbose' ]

	try:
		(opts, args) = getopt.getopt(args[1:], s_opts, l_opts)
	except getopt.error as msg:
		print(msg, file=sys.stderr)
		fatal(__doc__)

	for (o, a) in opts:
		if o in ('-A', '--generate-all'):
			generate_all = True
		elif o in ('-L', '--no-legend'):
			add_legend = False
		elif o in ('-o', '--output'):
			output_file = a
		elif o in ('-t', '--type'):
			if not a in types:
				fatal('Type %s not supported' % a)
			type = a
		elif o in ('-T', '--title'):
			title_str = a
		elif o in ('-v', '--verbose'):
			verbose = True

	if type == None and not generate_all:
		fatal('Need type of data files to process - (-t <type>)')

	return args

#------------------------------------------------------------------------------
def gen_title(fig, type, title_str):
	"""Sets the title for the figure based upon the type /or/ user title"""

	if title_str != None:
		pass
	elif type == 'aqd':
		title_str = 'Average Queue Depth'
	elif type == 'bnos':
		title_str = 'Block Numbers Accessed'
	elif type == 'q2d':
		title_str = 'Queue (Q) To Issue (D) Average Latencies'
	elif type == 'd2c':
		title_str = 'Issue (D) To Complete (C) Average Latencies'
	elif type == 'q2c':
		title_str = 'Queue (Q) To Complete (C) Average Latencies'

	title = fig.text(.5, .95, title_str, horizontalalignment='center')
	title.set_fontsize('large')

#------------------------------------------------------------------------------
def gen_labels(db, ax, type):
	"""Generate X & Y 'axis'"""

	#----------------------------------------------------------------------
	def gen_ylabel(ax, type):
		"""Set the Y axis label based upon the type"""

		if type == 'aqd':
			str = 'Number of Requests Queued'
		elif type == 'bnos':
			str = 'Block Number'
		else:
			str = 'Seconds'
		ax.set_ylabel(str)

	#----------------------------------------------------------------------
	xdelta = 0.1 * (db['max_x'] - db['min_x'])
	ydelta = 0.1 * (db['max_y'] - db['min_y'])

	ax.set_xlim(db['min_x'] - xdelta, db['max_x'] + xdelta)
	ax.set_ylim(db['min_y'] - ydelta, db['max_y'] + ydelta)
	ax.set_xlabel('Runtime (seconds)')
	ax.grid(True)
	gen_ylabel(ax, type)

#------------------------------------------------------------------------------
def generate_output(type, db):
	"""Generate the output plot based upon the type and database"""

	#----------------------------------------------------------------------
	def color(idx, style):
		"""Returns a color/symbol type based upon the index passed."""

		colors = [ 'b', 'g', 'r', 'c', 'm', 'y', 'k' ]
		l_styles = [ '-', ':', '--', '-.' ]
		m_styles = [ 'o', '+', '.', ',', 's', 'v', 'x', '<', '>' ]

		color = colors[idx % len(colors)]
		if style == 'line':
			style = l_styles[int((idx / len(l_styles)) % len(l_styles))]
		elif style == 'marker':
			style = m_styles[int((idx / len(m_styles)) % len(m_styles))]

		return '%s%s' % (color, style)

	#----------------------------------------------------------------------
	global add_legend, output_file, title_str, verbose

	if output_file != None:
		ofile = output_file
	else:
		ofile = '%s.png' % type

	if verbose:
		print('Generating plot into %s' % ofile)

	fig = plt.figure(figsize=plot_size)
	ax = fig.add_subplot(111)

	gen_title(fig, type, title_str)
	gen_labels(db, ax, type)

	idx = 0
	if add_legend:
		legends = []
	else:
		legends = None

	keys = []
	for file in six.iterkeys(db):
		if not file in ['min_x', 'max_x', 'min_y', 'max_y']:
			keys.append(file)

	keys.sort()
	for file in keys:
		dat = db[file]
		if type == 'bnos':
			ax.plot(dat['x'], dat['y'], color(idx, 'marker'),
				markersize=1)
		elif dat['ax'] == None:
			continue	# Don't add legend
		else:
			ax.plot(dat['ax'], dat['ay'], color(idx, 'line'),
				linewidth=1.0)
		if add_legend:
			legends.append(get_base(file))
		idx += 1

	if add_legend and len(legends) > 0:
		gen_legends(ax, legends)
	plt.savefig(ofile)

#------------------------------------------------------------------------------
def get_files(type):
	"""Returns the list of files for the -A option based upon type"""

	if type == 'bnos':
		files = []
		for fn in glob.glob('*c.dat'):
			for t in [ 'q2q', 'd2d', 'q2c', 'd2c' ]:
				if fn.find(t) >= 0:
					break
			else:
				files.append(fn)
	else:
		files = glob.glob('*%s.dat' % type)
	return files

#------------------------------------------------------------------------------
def do_bnos(files):
	for file in files:
		base = get_base(file)
		title_str = 'Block Numbers Accessed: %s' % base
		output_file = 'bnos_%s.png' % base
		generate_output(t, get_data([file]))

#------------------------------------------------------------------------------
def do_live(files):
	global plot_size

	#----------------------------------------------------------------------
	def get_live_data(fn):
		xs = []
		ys = []
		for line in open(fn, 'r'):
			f = line.rstrip().split()
			if f[0] != '#' and len(f) == 2:
				xs.append(float(f[0]))
				ys.append(float(f[1]))
		return xs, ys

	#----------------------------------------------------------------------
	def live_sort(a, b):
		if a[0] == 'sys' and b[0] == 'sys':
			return 0
		elif a[0] == 'sys' or a[2][0] < b[2][0]:
			return -1
		elif b[0] == 'sys' or a[2][0] > b[2][0]:
			return  1
		else:
			return  0

	#----------------------------------------------------------------------
	def turn_off_ticks(ax):
		for tick in ax.xaxis.get_major_ticks():
			tick.tick1On = tick.tick2On = False
		for tick in ax.yaxis.get_major_ticks():
			tick.tick1On = tick.tick2On = False
		for tick in ax.xaxis.get_minor_ticks():
			tick.tick1On = tick.tick2On = False
		for tick in ax.yaxis.get_minor_ticks():
			tick.tick1On = tick.tick2On = False

	#----------------------------------------------------------------------
	fig = plt.figure(figsize=plot_size)
	ax = fig.add_subplot(111)

	db = []
	for fn in files:
		if not os.path.exists(fn):
			continue
		(xs, ys) = get_live_data(fn)
		db.append([fn[:fn.find('_live.dat')], xs, ys])
	db.sort(live_sort)

	for rec in db:
		ax.plot(rec[1], rec[2])

	gen_title(fig, 'live', 'Active I/O Per Device')
	ax.set_xlabel('Runtime (seconds)')
	ax.set_ylabel('Device')
	ax.grid(False)

	ax.set_xlim(-0.1, db[0][1][-1]+1)
	ax.set_yticks([idx for idx in range(0, len(db))])
	ax.yaxis.set_ticklabels([rec[0] for rec in db])
	turn_off_ticks(ax)

	plt.savefig('live.png')
	plt.savefig('live.eps')

#------------------------------------------------------------------------------
if __name__ == '__main__':
	files = parse_args(sys.argv)

	if generate_all:
		output_file = title_str = type = None
		for t in types:
			files = get_files(t)
			if len(files) == 0:
				continue
			elif t == 'bnos':
				do_bnos(files)
			elif t == 'live':
				do_live(files)
			else:
				generate_output(t, get_data(files))
				continue

	elif len(files) < 1:
		fatal('Need data files to process')
	else:
		generate_output(type, get_data(files))
	sys.exit(0)
