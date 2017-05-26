#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fileencoding=utf-8


class EC2_Security_Group_Utility:

	def __init__(self):
		import boto3
		self.ec2=boto3.client('ec2')

	def set_vpc_id(self,vpc_id):
		if vpc_id:
			self.vpc_id=vpc_id
		else:
			vpcs=self.ec2.describe_vpcs()
			for v in vpcs['Vpcs']:
				if v['IsDefault']:
					self.vpc_id=v['VpcId']

		print "VPC_ID: %s" % self.vpc_id


	def get_default_vpc_id(self):
		vpcs=self.ec2.describe_vpcs()
		for v in vpcs['Vpcs']:
			if v['IsDefault']: return v['VpcId']

	def set_authorize_security_group(self,**kwargs):
		# ingress / egress
		authorize_type = kwargs.get('AuthorizeType')
		group_id = kwargs.get('GroupId')
		params   = kwargs.get('Params')
		prm = []
	
		for param in params:
			proto=param['proto']
			if proto == 'all':
				proto='-1'
			
			port=param['port']
			if port == 'all':
				port=-1

			prm.append({
				'IpProtocol': proto,
				'FromPort':   port,
				'ToPort':     port,
				'IpRanges':   [ { 'CidrIp': param['cidr'] } ]
			})
	
		# Ingress(入力方向)設定
		if authorize_type == 'ingress':
			self.ec2.authorize_security_group_ingress(
				GroupId       = group_id,
				IpPermissions = prm
			)
	
		# Egress(出力方向)設定
		elif authorize_type == 'egress':
			self.ec2.authorize_security_group_egress(
				GroupId       = group_id,
				IpPermissions = prm
			)

	def egress_revoke_all(self,group_id):
		# デフォルトでは全許可になっているので
		# 必要に応じて削除する
		egress=self.ec2.describe_security_groups(GroupIds=[group_id])['SecurityGroups'][0]['IpPermissionsEgress']
		self.ec2.revoke_security_group_egress(
			GroupId       = group_id,
			IpPermissions = egress
		)

	def set_security_group(self,**kwargs):

		group_name  = kwargs.get('GroupName')
		name        = kwargs.get('Name',group_name)
		description = kwargs.get('Name',group_name)
		egress_revoke_all = kwargs.get('egress_revoke_all')
		ingress     = kwargs.get('ingress')
		egress      = kwargs.get('egress')

		# GroupNameからGroupIdを探す
		try:
			group_id=self.ec2.describe_security_groups(GroupNames=[group_name])['SecurityGroups'][0]['GroupId']
			self.ec2.delete_security_group(GroupId=group_id)
			print "Delete Security Group: %s" % group_id
		except:
			pass
	
		group_id=self.ec2.create_security_group(
			VpcId       = self.vpc_id,
			GroupName   = group_name,
			Description = description
		)['GroupId']
	
		print "Create Security Group: %s | %s " % ( group_id, group_name )
	
		self.ec2.create_tags(
			Resources = [ group_id ],
			Tags      = [{ 'Key': 'Name', 'Value': name }]
		);

		if egress_revoke_all:
			self.egress_revoke_all(group_id)

		if ingress:
			self.set_authorize_security_group(
				AuthorizeType = 'ingress',
				GroupId       = group_id,
				Params        = ingress
			)
	
		if egress:
			self.set_authorize_security_group(
				AuthorizeType = 'egress',
				GroupId       = group_id,
				Params        = egress
			)
	
		return group_id

def load_yaml(fn):
	import sys, yaml
	from os.path import exists,basename
	print "Load: %s" % fn

	if not exists(fn):
		print "%s がありません" % fn
		sys.exit(2)

	data=None
	with open(fn,'r') as f:
		data=yaml.load(f)
		f.close()
	return data

def save_yaml(fn,data):
	import sys, yaml
	from os.path import exists,basename
	print "Save: %s" % fn

	with open(fn,'w') as f:
		f.write(yaml.dump(data))
		f.close()

def main():

	data=load_yaml('security_groups.yaml')
	sg=EC2_Security_Group_Utility()

	if 'vpc_id' in data:
		sg.set_vpc_id(data['vpc_id'])
	else:
		sg.set_vpc_id(None)
	
	for d in data['security_groups']:
		d['group_id']=sg.set_security_group(**d)


	save_yaml('security_groups_result.yaml',data)

if __name__ == '__main__':
	main()

