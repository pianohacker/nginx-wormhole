import asyncssh
import argparse
import datetime

from .common import VALID_SERVICE_NAMES

def service_name_argparse_type(value):
	if not VALID_SERVICE_NAMES:
		raise argparse.ArgumentTypeError(
			f'service names may contain up to 63 alphanumeric characters, containing but not starting with a dash'
		)

	return value

def main():
	parser = argparse.ArgumentParser(
		description = """Generate a SSH key for a given service.

This command generates an ED25519 key, appends the public key to the
`authorized_keys_SERVICE_NAME` file in the current directory, and outputs the
private key to stdout.""",
		formatter_class = argparse.RawTextHelpFormatter,
	)
	parser.add_argument(
		'service_name',
		metavar = 'SERVICE_NAME',
		type = service_name_argparse_type,
	)
	args = parser.parse_args()

	key = asyncssh.generate_private_key('ssh-ed25519')
	timestamp = datetime.datetime.now().isoformat(" ")
	key.set_comment(
		f'nginx-wormhole, service: {args.service_name} [{timestamp}]',
	)
	print(key.export_private_key().decode('utf-8'), end = '')
	key.append_public_key(f'authorized_keys_{args.service_name}')

if __name__ == '__main__':
	main()
