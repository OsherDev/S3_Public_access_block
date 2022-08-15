import boto3
import logging
import json
import os.path


logger = logging.getLogger()
s3_client = boto3.client('s3')

def list_s3_buckets():
    bucket_list = []
    print("Attempting to list buckets")
    try:
        response = s3_client.list_buckets()
        buckets = response["Buckets"]
        if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
            print("Successfully retrieved buckets")
            for bucket in buckets:
                bucket_list.append(bucket["Name"])
            return bucket_list
    except Exception as e:
        print("Error retrieving buckets:",e)
        
def evaluate_non_public_bucket(bucket):
    print(f"--------\n{bucket} is not public. Further evaluating...")
    try:
        access = s3_client.get_public_access_block(Bucket=bucket)
        for rule in access["PublicAccessBlockConfiguration"]:
            if not access["PublicAccessBlockConfiguration"][rule]:
                print(f"{bucket} has {rule} set to False. Adding to non-compliant list")
                return True
    except Exception as e:
        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            print(f'{bucket} has no Block Public Access enabled. Adding to non-compliant list')
            return True
        else:
            print(f"unexpected error: {e.response}")
    print(f"{bucket} has Block Public Access enabled. Excluding from list.\n--------")
    return False
            
def get_non_public_buckets(buckets):
    non_compliant_buckets = []     #List of buckets that are both not public and do not have block public access enabled
    for bucket in buckets:
        try:
            response = s3_client.get_bucket_policy_status(Bucket=bucket)
            if response['PolicyStatus']['IsPublic']:
                print(f"--------\n{bucket} is public. Excluding from list.\n--------")
            else:
                evaluation = evaluate_non_public_bucket(bucket)
                if evaluation:
                    non_compliant_buckets.append(bucket)
        except Exception as e:
            evaluation = evaluate_non_public_bucket(bucket)
            if evaluation:
                    non_compliant_buckets.append(bucket)
    output_file(non_compliant_buckets,"non_compliant_buckets")
    return    
def set_block_public_access(buckets):
    modified_buckets = []
    for bucket in buckets:
        try:
            print(f"Enabling Block Public Access for: {bucket}")
            input("Press enter to continue")
            response = s3_client.put_public_access_block(
                Bucket=bucket,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
                print(f"Successfully enabled Block Public Access on {bucket}")
                modified_buckets.append(bucket)
        except Exception as e:
            print(f"Error Enabling Block Public Access on {bucket}",e)
    output_file(modified_buckets,"modified_buckets")

            
def output_file(content,file_name):
    with open(f"{file_name}.txt","w") as file:
        for line in content:
            file.writelines(f"{line}\n")
    
def lambda_handler(event, context):
    #Get all buckets in account
    buckets = list_s3_buckets()
    
    #Get buckets with Block Public Access disabled, only if public is not already public
    if os.path.exists("non_compliant_buckets.txt"):
        with open("non_compliant_buckets.txt", "r") as file:
            buckets_for_remediation = [line.rstrip() for line in file.readlines()]
    else:
        get_non_public_buckets(buckets)
        with open("non_compliant_buckets.txt", "r") as file:
            buckets_for_remediation = [line.rstrip() for line in file.readlines()]
    print(buckets_for_remediation)
    
    #Set Block Public Access on all non-complaint buckets
    set_block_public_access(buckets_for_remediation)
    

    
