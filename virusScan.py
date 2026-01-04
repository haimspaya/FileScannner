import requests

class VirusScan:
    def __init__(self):
        self.url = "https://www.virustotal.com/gui/home/upload"

    def get_virusTotal_score(self, file_hash):
        api_key = "API_KEY"
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": api_key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return stats
        else:
            print("Error:", response.status_code)
            return None