import asyncio
import asyncssh
import collections
import logging
import os

from . import envconf
from .common import VALID_SERVICE_NAMES

conf = envconf.EnvConf(
	NW_LISTEN_HOST = (str, 'localhost'),
	NW_LISTEN_PORT = (int, 12322),
	NW_LOG_LEVEL = (lambda value: value.upper(), 'INFO'),
	NW_HOST_KEY = (str, ''),

	NW_NGINX_DIRECTORY = (str, '/etc/nginx/wormhole'),
	NW_NGINX_RELOAD_COMMAND = (str, 'systemctl reload nginx.service'),
	NW_DOMAIN = str,
	NW_SSL_CERTIFICATE = str,
	NW_SSL_PRIVATE_KEY = str,

	print_report = True,
)
logger = logging.getLogger('nginx-wormhole')

NGINX_COMMON_CONFIG = """listen 443 ssl;
listen [::]:443 ssl;

ssl on;
ssl_certificate {NW_SSL_CERTIFICATE};
ssl_certificate_key {NW_SSL_PRIVATE_KEY};

ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_dhparam /etc/nginx/dhparam.pem;
ssl_ciphers EECDH+AESGCM:EDH+AESGCM;
ssl_ecdh_curve secp384r1;
ssl_session_timeout  10m;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";
"""

def main():
	logging.basicConfig(
		format = '%(name)s: [%(levelname)s] %(message)s',
		level = conf.NW_LOG_LEVEL,
	)
	asyncssh.set_debug_level(2)

	with open(
		os.path.join(conf.NW_NGINX_DIRECTORY, 'common.conf'),
		'w',
		encoding = 'utf-8',
	) as common_conf:
		common_conf.write(NGINX_COMMON_CONFIG.format(**vars(conf)))

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

service_remote_ports = collections.defaultdict(lambda: set())

async def update_nginx_conf(service_name):
	if not service_remote_ports[service_name]:
		os.unlink(os.path.join(conf.NW_NGINX_DIRECTORY, f'service-{service_name}.conf'))
		return

	with open(
		os.path.join(conf.NW_NGINX_DIRECTORY, f'service-{service_name}.conf'),
		'w',
		encoding = 'utf-8',
	) as service_conf:
		service_conf.write(f"""server {{
	server_name {service_name}.{conf.NW_DOMAIN};
	include {conf.NW_NGINX_DIRECTORY}/common.conf;

	location / {{
		proxy_pass http://nginx_wormhole_{service_name.replace("-", "_")}_upstream;
	}}
}}

upstream nginx_wormhole_{service_name.replace("-", "_")}_upstream {{
""")
		for port in service_remote_ports[service_name]:
			service_conf.write(f"	server localhost:{port};\n")

		service_conf.write("}\n")
	
	proc = await asyncio.create_subprocess_exec(
		*conf.NW_NGINX_RELOAD_COMMAND.split(),
		stdin = asyncio.subprocess.DEVNULL,
	)
	await proc.wait()

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
			'Removing forwards for service %s to port(s) %s',
			self.service_name,
			', '.join(str(port) for port in self.remote_ports),
		)

		service_remote_ports[self.service_name] -= self.remote_ports

		asyncio.create_task(update_nginx_conf(self.service_name))

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
		service_remote_ports[self.service_name].add(listener.get_port())

		await update_nginx_conf(self.service_name)

		return listener

if __name__ == '__main__':
	main()
