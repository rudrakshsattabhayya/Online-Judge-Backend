# Generated by Django 4.2.1 on 2023-06-10 08:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Apis', '0010_alter_usermodel_hashedpassword'),
    ]

    operations = [
        migrations.AlterField(
            model_name='problemmodel',
            name='correctOutput',
            field=models.FileField(null=True, upload_to='correctOutputs'),
        ),
    ]
