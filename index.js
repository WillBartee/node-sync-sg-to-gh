'use strict';

const _ = require('lodash');
const rp = require('request-promise-native');

const GITHUB_METADATA_URL = 'https://api.github.com/meta';

const SCRIPT_NAME = require('path').basename(__filename).replace('.js', '');
const log = (message, ...args) => console.log(`${new Date().toISOString()} - [${SCRIPT_NAME}] -`, message, ...args);

let ec2;

function main(options) {
  for (let k of ['region', 'group_id']) {
    if (!options[k]) {
      return Promise.reject(new Error(`No ${k} was provided`));
    }
  }
  let metaData;
  let currentSGIngress;
  let ingressChanges;
  ec2 = getEC2(options);
  return Promise.resolve(log('Starting potential modification of security group ingress'))
    .then(() => getGithubMetaData())
    .then(md => metaData = md)
    .then(() => getGroupIngress(options))
    .then(csgi => currentSGIngress = csgi)
    .then(() => getIngressChanges(metaData, currentSGIngress))
    .then(ic => ingressChanges = ic)
    .then(() => applyIngressChanges(options, ingressChanges))
    .then(() => {
      return { metaData, currentSGIngress, ingressChanges };
    });
}

function getEC2(options) {
  const AWS = require('aws-sdk');

  AWS.CredentialProviderChain.defaultProviders = [
    new AWS.EC2MetadataCredentials(),
    new AWS.EnvironmentCredentials(),
    new AWS.SharedIniFileCredentials({ profile: options.profileName }),
    new AWS.SharedIniFileCredentials({ profile: 'default' })
  ];

  const chain = new AWS.CredentialProviderChain();
  chain.resolve((err, creds) => {
    AWS.config.credentials = creds;
  });
  AWS.config.update({
    credentialProvider: chain,
    region: options.region
  });

  return new AWS.EC2({ region: 'us-west-1' });
}

function getGithubMetaData() {
  log('Fetching the metadata from Github');
  return require('./test/githubmetadata'); // for testing
  return rp({
    method: 'GET',
    url: GITHUB_METADATA_URL,
    json: true,
    headers: { 'User-Agent': 'NOVA-Service-App' }
  })
    .catch(err => {
      throw new Error(`GithubMetadataError: Failed to get the metadata from Github => ${err.message}`);
    });
}

function getGroupIngress(options) {
  log('Fetching information about security group', options.group_id);
  return ec2.describeSecurityGroups({
    GroupIds: [options.group_id]
  }).promise()
    .then(dsgResults => {
      if (!dsgResults.SecurityGroups.length) {
        throw new Error(`EC2DEscribeGroupError: No groups found with group_id: ${options.group_id}`);
      }
      log('Found Security Group', dsgResults.SecurityGroups[0].GroupName);
      return dsgResults.SecurityGroups[0].IpPermissions;
    })
    .catch(err => {
      throw new Error(`EC2DescribeGroupError: Failed to describe the security-group ${options.group_id} => ${err.message}`);
    });
}

function getIngressChanges(metaData, currentSGIngress) {
  let hookIpRanges = metaData.hooks;
  let sgIpRanges = [];
  currentSGIngress.forEach(perm => {
    perm.IpRanges.forEach(range => {
      if (!sgIpRanges.includes(range.CidrIp)) {
        sgIpRanges.push(range.CidrIp);
      }
    });
  });
  let ignore = _.intersection(hookIpRanges, sgIpRanges);
  return {
    authorize: _.without(hookIpRanges, ...ignore),
    revoke: _.without(sgIpRanges, ...ignore)
  };
}

function applyIngressChanges(options, ingressChanges) {
  return Promise.resolve()
    .then(() => modifyIngress(options, 'authorize', ingressChanges))
    .then(() => modifyIngress(options, 'revoke', ingressChanges));
}

function modifyIngress(options, direction, ingressChanges) {
  if (ingressChanges[direction] && ingressChanges[direction].length) {
    log(`${direction}ing ingress rules for ${ingressChanges[direction]}`);
    return ec2[direction+'SecurityGroupIngress']({
      GroupId: options.group_id,
      IpPermissions: createRules(ingressChanges[direction])
    }).promise().catch(err => {
      throw new Error(`EC2GroupIngressError: Failed to ${direction} ingress to security-group ${options.group_id} => ${err.message}`);
    });
  }
  return Promise.resolve(log(`No ingress rules found to ${direction}`));
}

function createRules(ipAddresses) {
  const baseRule = (port, ips) => ({
    IpProtocol: 'tcp',
    FromPort: port,
    ToPort: port,
    IpRanges: ips.map(ip => ({ CidrIp: ip }))
  });
  return [
    baseRule(80, ipAddresses),
    baseRule(443, ipAddresses)
  ];
}

if (require.main === module) {
  main({
    region: process.env.AWS_REGION,
    group_id: process.env.SECURITY_GROUP_ID,
    profileName: process.env.AWS_PROFILE
  })
    .then((/*results*/) => log('Completed!\n'))
    .catch(err => log('ERROR => ', err));
}

module.exports = main;
