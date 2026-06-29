{
    "device_group": "RJUK-Inet",
    "address_groups": [
        {
            "name": "database-servers", 
            "member_names": ["db-server-01", "db-server-02"], 
            "description": "Database servers group"
        },
        {
            "name": "prod-apps",
            "filter_criteria": "tag.prod AND tag.app",
            "description": "Production applications (dynamic)"
        }
    ],
    "address_objects": [
        {"name": "db-server-01", "ip_address": "192.168.2.10", "description": "Database server 1"},
        {"name": "db-server-02", "ip_address": "192.168.2.11", "description": "Database server 2"},
        {"name": "app-server-01", "fqdn": "test1.example.net", "description": "Application server 1"}
    ],
    "url_categories": [
        {
            "name": "Production_Sites",
            "url_list": ["*.prod.example.com/", "*.production.com/"],
            "description": "created by PAN SDK"
        },
        {
            "name": "Testing_Sites",
            "url_list": ["*.test.local/", "*.dev.local/", "test2.example.com/", "test1.example.com/"],
            "description": "created by PAN SDK"
        }
    ],
    "service_objects": [
        {
            "name": "tcp-3389",
            "protocol": "tcp",
            "destination_port": "3389",
            "description": "created by PAN SDK"
        },
        {
            "name": "tcp-5570-5572",
            "protocol": "tcp",
            "destination_port": "5570-5572",
            "description": "created by PAN SDK"
        },
        {
            "name": "tcp-5570",
            "protocol": "tcp",
            "destination_port": "5570",
            "description": "created by PAN SDK"
        }
    ],
    "service_groups": [
        {
            "name": "grp-serv-test1", 
            "value": ["tcp-5570", "tcp-5570-5572"]
        }
    ]
}
