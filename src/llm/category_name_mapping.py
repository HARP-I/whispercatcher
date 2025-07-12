# Field mapping rules
field_mapping = {
    "Brand/OemName": "OemName",
    "OperatingSystem Version": "OS Version",
    "Network type": "Network Type",
    "Position/Location": "Location",
    "Longitude/Latitude": "Location",
    "List of all apps on the device": "App List",
    "AdvertisingID(adid)": "AdvertisingID",
    "IP": "IP Address",
    "Device Resolution": "Resolution",
}


def map_categories(categories):
    return [field_mapping.get(item, item) for item in categories]
