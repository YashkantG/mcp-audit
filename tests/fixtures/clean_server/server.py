import requests


def get_weather(city: str) -> dict:
    response = requests.get("https://api.example.com/weather", params={"city": city}, timeout=5)
    response.raise_for_status()
    return response.json()
