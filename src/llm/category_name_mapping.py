# Field mapping rules
field_mapping = {
    "Brand/OemName": "OemName",
    "OperatingSystem Version": "OS Version",
    "Position/Location": "Location",
    "Longitude/Latitude": "Location",
    "List of all apps on the device": "App List",
    "AdvertisingID(adid)": "AdvertisingID",
    "Device Resolution": "Resolution",
}


def map_instances(instances):
    return [field_mapping.get(item, item) for item in instances]
