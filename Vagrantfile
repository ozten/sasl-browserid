Vagrant::Config.run do |config|

    config.vm.box = "lucid32_2asdf.box"
    config.vm.box_url = "http://people.mozilla.org/~aking/sasl_browserid/lucid32_2.box"

    #                               VM    localhost                       
    config.vm.forward_port("web",   80,   8080)
    config.vm.forward_port("ldap",  1389, 801389)
    config.vm.forward_port("mysql", 3306, 803306)

    # Increase vagrant's patience during hang-y CentOS bootup
    # see: https://github.com/jedi4ever/veewee/issues/14
    config.ssh.max_tries = 50
    config.ssh.timeout   = 300

    # nfs needs to be explicitly enabled to run.

    config.vm.share_folder("v-root", "/home/vagrant/sasl-browserid", ".")

    # Add to /etc/hosts: 33.33.33.26 dev.saslbrowserid.org
    config.vm.network "33.33.33.26"

end
