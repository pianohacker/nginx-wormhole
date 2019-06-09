from collections.abc import Iterable
import os
import sys

REQUIRED_BUT_OMITTED = object()

def _tablize(data, out):
	num_columns = len(data[0])

	column_widths = [
		max(
			len(str(elem))
			for elem
			in column
		)
		for column
		in zip(*data)
	]

	for i, row in enumerate(data):
		print('  '.join(f'{{:<{width}}}' for width in column_widths).format(*row[:num_columns]), file = out)
		
		if i == 0:
			print('  '.join('-' * width for width in column_widths))

class EnvConf:
	def __init__(self, *, print_report = False, **kwargs):
		out = sys.stdout
		required_env_was_omitted = False

		report_table = [
			['ENV', 'VALUE', 'DEFAULT'],
		]

		for env_name, options in kwargs.items():
			if isinstance(options, Iterable):
				parser, default = options
			else:
				parser, default = options, REQUIRED_BUT_OMITTED

			if env_name in os.environ:
				value = parser(os.environ[env_name])
			else:
				if default is REQUIRED_BUT_OMITTED:
					required_env_was_omitted = True

				value = default

			setattr(self, env_name, value)

			if value is REQUIRED_BUT_OMITTED:
				report_table.append([
					env_name,
					'(MISSING)',
					'(REQUIRED)',
				])
			else:
				report_table.append([
					env_name,
					value or '(empty)',
					'(REQUIRED)' if default is REQUIRED_BUT_OMITTED else (default or '(empty)'),
				])

		if required_env_was_omitted:
			print_report = True
			out = sys.stderr

			print('ERROR: Required environment variables not provided:', file = sys.stderr)

		if print_report:
			_tablize(report_table, out)

		if required_env_was_omitted:
			raise SystemExit()
