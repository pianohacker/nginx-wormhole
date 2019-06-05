import asyncio
import asyncssh
import logging
import os

logger = logging.getLogger('nginx-wormhole')

def main():
	logging.basicConfig(
		format = '%(name)s: [%(levelname)s] %(message)s',
		level = os.environ.get('NW_LOG_LEVEL', 'info').upper(),
	)
	asyncssh.set_debug_level(2)

	loop = asyncio.get_event_loop()

	listen_host = os.environ.get('NW_LISTEN_HOST', 'localhost')
	listen_port = int(os.environ.get('NW_LISTEN_PORT', '12322'))

	loop.run_until_complete(start_server(listen_host, listen_port))

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
	if 'NW_HOST_KEY' in os.environ:
		return os.environ['NW_HOST_KEY']

	if not os.path.exists('server_id_ed25519'):
		asyncssh.generate_private_key('ssh-ed25519').write_private_key('server_id_ed25519')

	return open('server_id_ed25519', 'rb').read()

class WormholeServer(asyncssh.SSHServer):
	def connection_made(self, conn):
		self.conn = conn

	def password_auth_supported(self):
		return True

	def validate_password(self, username, password):
		self.service_name = username

		return True

	async def server_requested(self, listen_host, listen_port):
		if listen_host not in ('127.0.0.1', '::1', 'localhost'):
			logger.error("Request to listen on non-localhost address %s", listen_host)
			return False

		if listen_port != 0:
			logger.error("Request to listen on non-server-chosen port %d", listen_port)
			return False

		listener = await self.conn.forward_local_port(listen_host, listen_port, listen_host, listen_port)

		logger.info("Forwarding %s from local port %d", self.service_name, listener.get_port())

		return listener

main()
