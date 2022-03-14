registration_scheme = {
    'type': 'object',
    'properties': {
        "username": {'type': 'string',
                     'pattern': "^[a-zA-Z0-9-_]+$"},
        'email': {'type': 'string',
                  'pattern': """(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"""},
        'password': {'type': 'string', 'pattern': '^(?=.*?[a-z])(?=.*?[0-9]).{8,}$'},
    },
    'required': ['username', 'email', 'password']
}

announcement_scheme_create = {
    'type': 'object',
    'properties': {
        "title": {'type': 'string',
                  "pattern": "^[?!;_a-zA-Zа-яА-ЯёЁ0-9<>()-:'\s]+$"},
        "text": {'type': 'string',
                 'pattern': "^[?!;_a-zA-Zа-яА-ЯёЁ0-9<>()-:'\s]+$"},
        'cetegory_id': {'type': 'integer'},
    },
    "required": ['title']
}

announcement_scheme_update = {
    'type': 'object',
    'properties': {
        'title': {'type': 'string',
                  "pattern": "^[?!;_a-zA-Zа-яА-ЯёЁ0-9<>()-:'\s]+$"},
        'text': {'type': 'string',
                 'pattern': "^[?!;_a-zA-Zа-яА-ЯёЁ0-9<>()-:'\s]+$"},
    }
}

category_announcement_scheme_create_or_update = {
    'type': 'object',
    'properties': {
        'title': {'type': 'string',
                  'pattern': "^[?!;_a-zA-Zа-яА-ЯёЁ0-9<>()-:'\s]+$"},
    },
    'required': ['title']
}

