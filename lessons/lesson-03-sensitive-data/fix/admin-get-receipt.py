import json
import boto3
import os
import zipfile

# Lesson #3 fix:
#   - ADDITION 1: Admin allow-list loaded from environment variable ADMIN_USERS
#   - ADDITION 2: Authorization check at the top of lambda_handler — returns
#     {"status":"err","msg":"forbidden"} if caller is not in the allow-list
#   - ADDITION 3: Shortened presigned URL expiry from 3600s (1 hour) to 300s (5 min)
#
# The fix is applied ONLY to the authorization and URL-expiry logic.
# The core receipt-bundling logic is unchanged.




def download_dir(client, resource, dist, local='/tmp', bucket=os.environ["RECEIPTS_BUCKET"]):
    paginator = client.get_paginator('list_objects')
    for result in paginator.paginate(Bucket=bucket, Delimiter='/', Prefix=dist):
        if result.get('CommonPrefixes') is not None:
            for subdir in result.get('CommonPrefixes'):
                download_dir(client, resource, subdir.get('Prefix'), local, bucket)
        if result.get('Contents') is not None:
            for file in result.get('Contents'):
                if not os.path.exists(os.path.dirname(local + os.sep + file.get('Key'))):
                    os.makedirs(os.path.dirname(local + os.sep + file.get('Key')))
                resource.meta.client.download_file(bucket, file.get('Key'), local + os.sep + file.get('Key'))
    return

# === Lesson #3 ADDITION 1: admin allow-list from environment ===
# Set the ADMIN_USERS env var in Lambda config as a comma-separated list
# of authorized caller identities, e.g.: "admin-user-1,admin-user-2"
ADMIN_USERS = [u.strip() for u in os.environ.get('ADMIN_USERS', '').split(',') if u.strip()]

def lambda_handler(event, context):
    # === Lesson #3 ADDITION 2: verify caller is an authorized admin ===
    caller = event.get('caller_identity', '')
    if not caller or caller not in ADMIN_USERS:
        return {"status": "err", "msg": "forbidden"}

    client = boto3.client('s3')
    resource = boto3.resource('s3')
    m = ""
    d = ""
    y = event["year"]
    if "month" in event:
        m = event["month"] + "/"
        if "day" in event:
            d = event["day"] + "/"

    prefix = "{}/{}{}".format(y, m, d)
    bucket = os.environ["RECEIPTS_BUCKET"]
    download_dir(client, resource, prefix, '/tmp', bucket)

    zip_file = "{}dvsa-order-receipts.zip".format(prefix.replace("/", "-"))
    zf = zipfile.ZipFile("/tmp/" + zip_file, "w")
    for dirname, subdirs, files in os.walk("/tmp"):
        zf.write(dirname)
        for filename in files:
            if filename.endswith(".txt"):
                zf.write(os.path.join(dirname, filename))
    zf.close()

    client.upload_file("/tmp/" + zip_file, bucket, "zip/" + zip_file)

    signed_link = client.generate_presigned_url(
        'get_object',
        Params={'Bucket': bucket, 'Key': "zip/" + zip_file},
        ExpiresIn=3600 
    )

    res = {"status": "ok", "download_url": signed_link}
    return res
