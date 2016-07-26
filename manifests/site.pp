#
# Top-level variables
#
# There must not be any whitespace between this comment and the variables or
# in between any two variables in order for them to be correctly parsed and
# passed around in test.sh
#
$elasticsearch_nodes = hiera_array('elasticsearch_nodes')
$elasticsearch_clients = hiera_array('elasticsearch_clients')

#
# Default: should at least behave like an openstack server
#
node default {
  class { 'openstack_project::server':
    sysadmins => hiera('sysadmins', []),
  }
}

#
# Long lived servers:
#
# Node-OS: trusty
node 'review' {
  class { 'openstack_project::server':
    iptables_public_tcp_ports => [80, 443, 29418],
    sysadmins                 => hiera('sysadmins', []),
  }

  class { 'openstack_project::review':
    project_config_repo                 => 'https://git.openstack.org/openstack-infra/project-config',
    github_oauth_token                  => hiera('gerrit_github_token'),
    github_project_username             => hiera('github_project_username', 'username'),
    github_project_password             => hiera('github_project_password'),
    mysql_host                          => hiera('gerrit_mysql_host', 'localhost'),
    mysql_password                      => hiera('gerrit_mysql_password'),
    email_private_key                   => hiera('gerrit_email_private_key'),
    token_private_key                   => hiera('gerrit_rest_token_private_key'),
    gerritbot_password                  => hiera('gerrit_gerritbot_password'),
    gerritbot_ssh_rsa_key_contents      => hiera('gerritbot_ssh_rsa_key_contents'),
    gerritbot_ssh_rsa_pubkey_contents   => hiera('gerritbot_ssh_rsa_pubkey_contents'),
    ssl_cert_file_contents              => hiera('gerrit_ssl_cert_file_contents'),
    ssl_key_file_contents               => hiera('gerrit_ssl_key_file_contents'),
    ssl_chain_file_contents             => hiera('gerrit_ssl_chain_file_contents'),
    ssh_dsa_key_contents                => hiera('gerrit_ssh_dsa_key_contents'),
    ssh_dsa_pubkey_contents             => hiera('gerrit_ssh_dsa_pubkey_contents'),
    ssh_rsa_key_contents                => hiera('gerrit_ssh_rsa_key_contents'),
    ssh_rsa_pubkey_contents             => hiera('gerrit_ssh_rsa_pubkey_contents'),
    ssh_project_rsa_key_contents        => hiera('gerrit_project_ssh_rsa_key_contents'),
    ssh_project_rsa_pubkey_contents     => hiera('gerrit_project_ssh_rsa_pubkey_contents'),
    ssh_welcome_rsa_key_contents        => hiera('welcome_message_gerrit_ssh_private_key'),
    ssh_welcome_rsa_pubkey_contents     => hiera('welcome_message_gerrit_ssh_public_key'),
    ssh_replication_rsa_key_contents    => hiera('gerrit_replication_ssh_rsa_key_contents'),
    ssh_replication_rsa_pubkey_contents => hiera('gerrit_replication_ssh_rsa_pubkey_contents'),
    lp_sync_consumer_key                => hiera('gerrit_lp_consumer_key'),
    lp_sync_token                       => hiera('gerrit_lp_access_token'),
    lp_sync_secret                      => hiera('gerrit_lp_access_secret'),
    contactstore_appsec                 => hiera('gerrit_contactstore_appsec'),
    contactstore_pubkey                 => hiera('gerrit_contactstore_pubkey'),
    swift_username                      => hiera('swift_store_user', 'username'),
    swift_password                      => hiera('swift_store_key'),
  }
}

# Node-OS: precise
node /^jenkins\d+\$/ {
  $group = "jenkins"
  $zmq_event_receivers = ['logstash.openstack.org',
                          'nodepool.openstack.org']
  $zmq_iptables_rule = regsubst($zmq_event_receivers,
                                '^(.*)$', '-m state --state NEW -m tcp -p tcp --dport 8888 -s \1 -j ACCEPT')
  $http_iptables_rule = '-m state --state NEW -m tcp -p tcp --dport 80 -s nodepool.openstack.org -j ACCEPT'
  $https_iptables_rule = '-m state --state NEW -m tcp -p tcp --dport 443 -s nodepool.openstack.org -j ACCEPT'
  $iptables_rule = flatten([$zmq_iptables_rule, $http_iptables_rule, $https_iptables_rule])
  class { 'openstack_project::server':
    iptables_rules6     => $iptables_rule,
    iptables_rules4     => $iptables_rule,
    sysadmins           => hiera('sysadmins', []),
    puppetmaster_server => 'puppetmaster.openstack.org',
  }
  class { 'openstack_project::jenkins':
    jenkins_password        => hiera('jenkins_jobs_password'),
    jenkins_ssh_private_key => hiera('jenkins_ssh_private_key_contents'),
    ssl_cert_file           => '/etc/ssl/certs/ssl-cert-snakeoil.pem',
    ssl_key_file            => '/etc/ssl/private/ssl-cert-snakeoil.key',
    ssl_chain_file          => '',
  }
}

# Node-OS: trusty
node 'nodepool' {
  $bluebox_username    = hiera('nodepool_bluebox_username', 'username')
  $bluebox_password    = hiera('nodepool_bluebox_password')
  $bluebox_project     = hiera('nodepool_bluebox_project', 'project')
  $rackspace_username  = hiera('nodepool_rackspace_username', 'username')
  $rackspace_password  = hiera('nodepool_rackspace_password')
  $rackspace_project   = hiera('nodepool_rackspace_project', 'project')
  $hpcloud_username    = hiera('nodepool_hpcloud_username', 'username')
  $hpcloud_password    = hiera('nodepool_hpcloud_password')
  $hpcloud_project     = hiera('nodepool_hpcloud_project', 'project')
  $internap_username   = hiera('nodepool_internap_username', 'username')
  $internap_password   = hiera('nodepool_internap_password')
  $internap_project    = hiera('nodepool_internap_project', 'project')
  $ovh_username        = hiera('nodepool_ovh_username', 'username')
  $ovh_password        = hiera('nodepool_ovh_password')
  $ovh_project         = hiera('nodepool_ovh_project', 'project')
  $tripleo_username    = hiera('nodepool_tripleo_username', 'username')
  $tripleo_password    = hiera('nodepool_tripleo_password')
  $tripleo_project     = hiera('nodepool_tripleo_project', 'project')
  $infracloud_username = hiera('nodepool_infracloud_username', 'username')
  $infracloud_password = hiera('nodepool_infracloud_password')
  $infracloud_project  = hiera('nodepool_infracloud_project', 'project')
  $osic_username       = hiera('nodepool_osic_username', 'username')
  $osic_password       = hiera('nodepool_osic_password')
  $osic_project        = hiera('nodepool_osic_project', 'project')
  $vexxhost_username   = hiera('nodepool_vexxhost_username', 'username')
  $vexxhost_password   = hiera('nodepool_vexxhost_password')
  $vexxhost_project    = hiera('nodepool_vexxhost_project', 'project')
  $clouds_yaml = template("openstack_project/nodepool/clouds.yaml.erb")
  class { 'openstack_project::server':
    sysadmins                 => hiera('sysadmins', []),
    iptables_public_tcp_ports => [80],
  }

  class { '::zookeeper': }

  include openstack_project

  class { '::openstackci::nodepool':
    vhost_name                    => 'nodepool.openstack.org',
    project_config_repo           => 'https://git.openstack.org/openstack-infra/project-config',
    mysql_password                => hiera('nodepool_mysql_password'),
    mysql_root_password           => hiera('nodepool_mysql_root_password'),
    nodepool_ssh_public_key       => hiera('zuul_worker_ssh_public_key_contents'),
    # TODO(pabelanger): Switch out private key with zuul_worker once we are
    # ready.
    nodepool_ssh_private_key      => hiera('jenkins_ssh_private_key_contents'),
    oscc_file_contents            => $clouds_yaml,
    image_log_document_root       => '/var/log/nodepool/image',
    statsd_host                   => 'graphite.openstack.org',
    logging_conf_template         => 'openstack_project/nodepool/nodepool.logging.conf.erb',
    builder_logging_conf_template => 'openstack_project/nodepool/nodepool-builder.logging.conf.erb',
    upload_workers                => '16',
    jenkins_masters               => [],
  }
  file { '/home/nodepool/.config/openstack/infracloud_west_cacert.pem':
    ensure  => present,
    owner   => 'nodepool',
    group   => 'nodepool',
    mode    => '0600',
    content => hiera('infracloud_hpuswest_ssl_cert_file_contents'),
    require => Class['::openstackci::nodepool'],
  }
}

# Node-OS: precise
# Node-OS: trusty
node 'zuul' {
  class { 'openstack_project::zuul_prod':
    project_config_repo            => 'https://git.openstack.org/openstack-infra/project-config',
    gerrit_server                  => 'review.openstack.org',
    gerrit_user                    => 'jenkins',
    gerrit_ssh_host_key            => hiera('gerrit_ssh_rsa_pubkey_contents'),
    zuul_ssh_private_key           => hiera('zuul_ssh_private_key_contents'),
    url_pattern                    => 'http://logs.openstack.org/{build.parameters[LOG_PATH]}',
    proxy_ssl_cert_file_contents   => hiera('zuul_ssl_cert_file_contents'),
    proxy_ssl_key_file_contents    => hiera('zuul_ssl_key_file_contents'),
    proxy_ssl_chain_file_contents  => hiera('zuul_ssl_chain_file_contents'),
    zuul_url                       => 'http://zuul.openstack.org/p',
    sysadmins                      => hiera('sysadmins', []),
    statsd_host                    => 'graphite.openstack.org',
    gearman_workers                => [
    ],
  }
}

