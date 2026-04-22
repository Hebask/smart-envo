from app import create_app
from app.dns_sniffer import start_sniffer

app = create_app()

with app.app_context():
    start_sniffer()
