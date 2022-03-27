# Python Program for creating a connection
import boto3
import botocore
import paramiko
import time
import argparse
import random
from collections import defaultdict
from botocore.exceptions import ClientError

aws_key = ''
aws_secret = ''
C2group = 'C2Default'
Region='us-east-1'

def Create_Instance(key, secret):
    global Region
    try:
        ec2 = boto3.client('ec2',
                           Region,
                           aws_access_key_id=key,
                           aws_secret_access_key=secret)

        # This function will describe all the instances
        # with their current state
        response = ec2.describe_instances()
    except Exception as e:
        print("Error while connecting to AWS " + str(e))
        exit(0)
    # print(response)
    try:
    #if 1==1:
        keyname = 'ec2-keypair-' + str(time.localtime().tm_sec) + str(time.localtime().tm_min)
        keyfilename=keyname + '.pem'
        outfile = open(keyname + '.pem', 'w')

        # call the boto ec2 function to create a key pair
        key_pair = ec2.create_key_pair(KeyName=keyname)
        # print(key_pair)
        # capture the key and store it in a file
        KeyPairOut = str(key_pair["KeyMaterial"])
        # print(KeyPairOut)
        outfile.write(KeyPairOut)
        outfile.close()
        print("key " + keyname + " created and writen to file : " + keyfilename)
    except Exception as e:
        print("Error while creating SSH private key " + str(e))
        exit(0)

    groupexist = 0

    try:
        print("Checking if Security Group with Name ( " + C2group + " )")
        response = ec2.describe_security_groups(GroupNames=[C2group])
        # print(response)
        security_group_id = response['SecurityGroups'][0]['GroupId']
        # print(security_group_id)
        groupexist = 1

    except ClientError as e:
        print("Error checking the security group ( " + str(e) + " )")

    if groupexist == 0:
        print("Creating New Security Group with Name")
        response = ec2.describe_vpcs()
        vpc_id = response.get('Vpcs', [{}])[0].get('VpcId', '')

        try:
            response = ec2.create_security_group(GroupName=C2group,
                                                 Description='DESCRIPTION',
                                                 VpcId=vpc_id)
            security_group_id = response['GroupId']
            print('Security Group Created %s in vpc %s.' % (security_group_id, vpc_id))

            data = ec2.authorize_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[
                    {'IpProtocol': 'tcp',
                     'FromPort': 80,
                     'ToPort': 9999,
                     'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                    {'IpProtocol': 'tcp',
                     'FromPort': 22,
                     'ToPort': 22,
                     'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
                ])
            print('Ingress Successfully Set %s' % data)
        except ClientError as e:
            print("Error Creating the security group ( " + str(e) + " )")

    try:
        # Function for running instances
        print("Creating AWS Instance")
        conn = ec2.run_instances(InstanceType="t2.micro",
                                 MaxCount=1,
                                 MinCount=1,
                                 ImageId="ami-04505e74c0741db8d",
                                 KeyName=keyname,
                                 SecurityGroups=[C2group])
        print("AWS Instance Sucessfully created with ID (" + conn["Instances"][0][
            "InstanceId"] + ") and details : " + str(conn))
    except ClientError as e:
        print("Error Creating AWS Instance ( " + str(e) + " )")

    instanceid = conn["Instances"][0]["InstanceId"]

    print("Waiting 3 minutes for Instance to be ready")
    time.sleep(200)
    print("Getting New Instance Public IP")
    running_instances = ec2.describe_instances()
    ec2info = defaultdict()
    #print(running_instances)
    found = 0
    #print(running_instances["Reservations"])
    for instance in running_instances["Reservations"]:
        #print(instance['Instances'][0]['InstanceId'])
        if instance['Instances'][0]['InstanceId'].find(instanceid.strip()) > -1:
            #print(instance)
            #print(instance['Instances'][0]["PublicIpAddress"])
            IP = instance['Instances'][0]["PublicIpAddress"]
            print("Instance Public IP is : "+IP)
            found = 1
    if found == 0:
        print("did not find instance")
        exit(-1)




    try:
        print("installing NinjaC2 in the instance")
        #print(keyname + ".pem")
        key = paramiko.RSAKey.from_private_key_file(keyname + ".pem")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Here 'ubuntu' is user name and 'instance_ip' is public IP of EC2
        client.connect(hostname=IP, username="ubuntu", pkey=key)
        cmd = "cd /opt/;sudo git clone https://github.com/ahmedkhlief/Ninja.git;cd /opt/Ninja/;sudo ./install.sh"
        # cmd="sudo touch /opt/test"

        _stdin, _stdout, _stderr = client.exec_command(cmd)

        #print(_stdout.read().decode())
        #print(_stderr.read().decode())
        if len(_stderr.read())>0:
            print("Issue installing NinjaC2 in the new Instance")
        client.close()

    except Exception as e:
        print(e)

    print("Connect to instnace : ssh -i "+keyfilename+" -l ubuntu "+IP)
    print("Note : Don't forget to change the key permissions : chmod 400 "+keyfilename)
    file=open("connect"+IP+".sh","w")
    file.write("ssh -i "+keyfilename+" -l ubuntu "+IP)
    file.close()




def main():
    global aws_key,aws_secret,Region
    parser = argparse.ArgumentParser()
    parser.add_argument("-k","--key", help="AWS Key ID - Must be generated through AWS portal")
    parser.add_argument("-s","--secret",help="AWS Key Secret - Must be generated through AWS portal")
    parser.add_argument("-r","--region",help="Region to create the new instance - Default is us-east-1 ")
    args = parser.parse_args()
    if args.key is not None and args.secret is not None:
        aws_key=args.key
        aws_secret=args.secret
        if args.region is not None:
            Region=args.region
        Create_Instance(aws_key, aws_secret)
    else:
        print("Needed arguments are missing , please use --help to show help info")


main()
