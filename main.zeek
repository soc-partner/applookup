##! This module contains some convenience mechanisms for identying applications
##! from various fields
##! Inspired by domain-tld and appid plugins
##! Relies on:
##!
##!   https://publicsuffix.org/
##!   https://publicsuffix.org/list/public_suffix_list.dat
##!   https://github.com/ntop/nDPI/tree/dev/src/lib
##!
##! Author: Romain <romain@soc-partner.com>

module applookup;

@load ./effectivename.zeek
@load ./knownapp.zeek

# Add the new optional fields to the Conn::Info record that must be logged in conn.log
redef record Conn::Info += { app_ename:string &optional &log; };
redef record Conn::Info += { app_etld:string &optional &log; };
redef record Conn::Info += { app_kdomain:string &optional &log; };
redef record Conn::Info += { app_kip:string &optional &log; };


# Define an event that will be triggered when a connection state is removed
event connection_state_remove(c: connection) {
    local domain = "";

    # Check if the connection contains HTTP information and a valid domain
    if ( c?$http && c$http?$host && c$http$host != /([[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3})((\:[[:digit:]]{1,5})?)/ )
        domain = c$http$host;

    # Otherwise, check if the connection contains SSL information and a valid domain
    else if ( c?$ssl && c$ssl?$server_name && c$ssl$server_name != /([[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3})((\:[[:digit:]]{1,5})?)/ )
        domain = c$ssl$server_name;

    # If a valid domain name is found, compute it effective application and tld
    if (domain != "") {
        local ename = EffectiveName::effective_name(domain);
        c$conn$app_ename = ename$application;
        c$conn$app_etld = ename$tld;

        # TODO: Check if the domain name is a known application
        # local app_kdomain = KnownName::kname_domain(domain);
        # if ( app_kdomain != "" ) c$conn$app_kdomain = app_kdomain;
        # else c$conn$app_kdomain = domain;
    }

    # If the connection contains id (IPs/ports) 
    if (c?$id) {
        local app_ip: KnownApp::app = KnownApp::search_ip(c$conn$id$resp_h); # Check if the destination IP is a known application
        if (app_ip$exist == F) # Otherwise, check the source IP
            app_ip = KnownApp::search_ip(c$conn$id$origin_h);
        if (app_ip$exist == T)
            c$conn$app_kip = app_ip$name;
    }
}

