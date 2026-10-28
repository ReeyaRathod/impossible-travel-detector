import json
from datetime import datetime
import requests
from math import radians, sin, cos, sqrt, atan2
from rich.console import Console
from rich.table import Table

console = Console()
LOG_FILE = "login_logs.json"

def get_geoip(ip):
	"""Fetches latitude, longitude, and city for an IP address using a free geo-lookup API."""
	try:
		response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
		data = response.json()
		if data["status"] == "success":
			return {
				"city": data.get("city", "Unknown"),
				"country": data.get("country", "Unknown"),
				"lat": data["lat"],
				"lon": data["lon"]
			}
	except Exception as e:
		console.print(f"[bold red][!] Error fetching IP location for {ip}: {e}[/bold red]")
	return None

def calculate_distance(lat1, lon1, lat2, lon2):
	"""Calculates distance between two GPS coordination in kilometers using the Haversine formula."""
	R = 6371.0 # Earth radius in km
	dlat = radians(lat2 - lat1)
	dlon = radians(lon2 - lon1)
	a = sin(dlat / 2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2)**2
	c = 2 * atan2(sqrt(a), sqrt(1 - a))
	return R * c

def analyze_logs():
	with open(LOG_FILE, "r") as f:
		logs = json.load(f)

	table = Table(title="Impossible Travel Security Analyzer", style="blue")
	table.add_column("Username", style="cyan")
	table.add_column("Time 11 -> Time 2", style="magenta")
	table.add_column("Location 1 -> Location 2", style="yellow")
	table.add_column("Distance", style="blue")
	table.add_column("Status", style="bold")

	logs = sorted(logs, key=lambda x: x["timestamp"])

	for i in range(len(logs) - 1):
		log1 = logs[i]
		log2 = logs[i+1]

		if log1["username"] == log2["username"]:
			loc1 = get_geoip(log1["ip"])
			loc2 = get_geoip(log2["ip"])

			if loc1 and loc2:
				dist = calculate_distance(loc1["lat"], loc1["lon"], loc2["lat"], loc2["lon"])

				fmt = "%Y-%m-%d %H:%M:%S"
				t1 = datetime.strptime(log1["timestamp"], fmt)
				t2 = datetime.strptime(log2["timestamp"], fmt)
				hours_diff = abs((t2 - t1).total_seconds()) / 3600.0

				if hours_diff == 0:
					hours_diff = 0.01

				speed = dist / hours_diff

				if speed > 900:
					status = "[bold red] IMPOSSIBLE TRAVEL DETECTED[/bold red]"
				else:
					status = "[green]NORMAL[/green]"

				loc_str1 = f"{loc1['city']}, {loc1['country']}"
				loc_str2 = f"{loc2['city']}, {loc2['country']}"
				time_str = f"{log1['timestamp']} -> {log2['timestamp']}"
				dist_str = f"{int(dist)} km ({int(speed)} km/h)"

				table.add_row(log1["username"], time_str, f"{loc_str1} \n-> {loc_str2}", dist_str, status)
	console.print(table)

if __name__ == "__main__":
	console.print("[cyan][*] Analyzing authentication logs for geographic anomalies...[/cyan]")
	analyze_logs()
