##! This module contains some convenience mechanisms for identying applications
##! from various fields
##! Inspired from domain-tld and appid plugins
##!
##!   https://publicsuffix.org/
##!   https://publicsuffix.org/list/public_suffix_list.dat
##!   https://github.com/ntop/nDPI/tree/dev/src/lib
##!
##! Author: Romain Ollier <romain@soc-partner.com>

module applookup;

@load ./effectivename.zeek
@load ./knownname.zeek

redef record Conn::Info += { app_ename:string &optional &log; };
redef record Conn::Info += { app_etld:string &optional &log; };
redef record Conn::Info += { app_kdomain:string &optional &log; };
redef record Conn::Info += { app_kip:string &optional &log; };


event connection_state_remove(c: connection)
    {
    local domain = "";
    if ( c?$http && c$http?$host && c$http$host != /([[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3})((\:[[:digit:]]{1,5})?)/ )
	{
	domain = c$http$host;
        }
    else if ( c?$ssl && c$ssl?$server_name && c$ssl$server_name != /([[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3})((\:[[:digit:]]{1,5})?)/ )
	{
	domain = c$ssl$server_name;
        }
    if (domain != "")
	{
	local ename = EffectiveName::ename(domain);
      	c$conn$app_ename = ename$application;
      	c$conn$app_etld = ename$tld;
	local app_kdomain = KnownName::kname_domain(domain);
	if ( app_kdomain != "" ) c$conn$app_kdomain = app_kdomain;
	else c$conn$app_kdomain = domain;
	}
    if (c?$id) 
	{
	local app_kip = KnownName::kname_ip(c$conn$id$orig_h);
	if (app_kip == "") app_kip = KnownName::kname_ip(c$conn$id$resp_h);
	if (app_kip != "") c$conn$app_kip = app_kip;
	}
    }

