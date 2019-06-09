import asyncio
import asyncssh
import logging
import os
import re

from . import envconf

VALID_SERVICE_NAMES = re.compile(r'^[a-z0-9][a-z0-9]{,62}')

conf = envconf.EnvConf(
	NW_LISTEN_HOST = (str, 'localhost'),
	NW_LISTEN_PORT = (int, 12322),
	NW_LOG_LEVEL = (lambda value: value.upper(), 'info'),
	NW_HOST_KEY = (str, ''),

	print_report = True,
)
logger = logging.getLogger('nginx-wormhole')

def main():
	logging.basicConfig(
		format = '%(name)s: [%(levelname)s] %(message)s',
		level = conf.NW_LOG_LEVEL,
	)
	asyncssh.set_debug_level(2)

	loop = asyncio.get_event_loop()

	loop.run_until_complete(start_server(
		conf.NW_LISTEN_HOST,
		conf.NW_LISTEN_PORT,
	))

	try:
		loop.run_forever()
	except KeyboardInterrupt:
		pass

async def start_server(listen_host: str, listen_port: int):
	await asyncssh.create_server(
		WormholeServer,
		listen_host,
		listen_port,
		server_host_keys = [get_or_generate_server_key()],
	)

def get_or_generate_server_key():
	if conf.NW_HOST_KEY:
		return conf.NW_HOST_KEY

	if not os.path.exists('server_id_ed25519'):
		asyncssh.generate_private_key('ssh-ed25519').write_private_key('server_id_ed25519')

	return open('server_id_ed25519', 'rb').read()

class WormholeServer(asyncssh.SSHServer):
	def __init__(self):
		self.conn = None
		self.remote_ports = set()
		self.service_name = None

	def connection_made(self, conn):
		self.conn = conn
	
	def connection_lost(self, exc):
		if not self.service_name or not self.remote_ports:
			return

		logger.info(
			'Removing forwards for service %s to ports %s',
			self.service_name,
			', '.join(str(port) for port in self.remote_ports),
		)

	def begin_auth(self, service_name):
		if VALID_SERVICE_NAMES.match(service_name):
			self.service_name = service_name
			try:
				self.conn.set_authorized_keys(f"authorized_keys_{service_name}")
			except FileNotFoundError:
				logger.warning(f"No authorized keys for service {service_name}")

		return True

	async def server_requested(self, listen_host, listen_port):
		if listen_host not in ('127.0.0.1', '::1', 'localhost'):
			logger.error(f"Request to listen on non-localhost address {listen_host}")
			return False

		if listen_port != 0:
			logger.error(f"Request to listen on non-server-chosen port {listen_port}")
			return False

		listener = await self.conn.forward_local_port(listen_host, listen_port, listen_host, listen_port)

		logger.info(f"Forwarding {self.service_name} from local port {listener.get_port()}")
		self.remote_ports.add(listener.get_port())

		return listener

if __name__ == '__main__':
	main()
