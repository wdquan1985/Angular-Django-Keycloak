from django.db.models.signals import post_migrate
from django.contrib.auth.models import User

def init_db(sender, **kwargs):
    if sender.name == "users":
        if not User.objects.filter(username='admin').exists():
            User.objects.create_superuser('admin', 'first@test.com', 'cctf@CSF')

post_migrate.connect(init_db)

