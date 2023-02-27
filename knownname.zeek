# figure out what stuff is

module KnownName;

export {
    global kname_ip: function(ip: addr): string;
    global kname_domain: function(domain: string): string;
}

type t_ips: record {
    ips: subnet;
    };
type t_domains: record {
    domains: pattern;
    };
type t_name: record {
    name: string;
    };

global nets: table[subnet] of t_name;
global domains: table[pattern] of t_name;


function kname_ip(ip: addr): string
    {
    if ( ip in nets)
        {
	local result = nets[ip]$name;
	return result[0] + to_lower(result)[1:];
        }
    return "";
    }

function kname_domain(domain: string): string
    {
    for ( i in domains )
	{
	if ( i in domain )
	    {
	    local result = domains[i]$name;
	    return result;
	    }
	}
    return "";
    }

#event Input::end_of_data(name: string, source: string)
#    {
#    if ( "nets.in" in source )print fmt("I have %d nets", |nets|);
#    if ( "domains.in" in source )print fmt("I have %d domains", |domains|);
#    local test1: vector of addr = vector(192.168.1.1, 52.215.168.10);
#    for ( i in test1 )
#        {
#        print fmt("IP: %s", test1[i]);
#        print fmt("    Known: %s", kname_ip(test1[i]));
#        }   
#    local test2: vector of string = vector("test.aiv-delivery.net", "test.aiv-delivery.net.test");
#    for ( i in test2 )
#        {
#        print fmt("domain: %s", test2[i]);
#        print fmt("    Known: %s", kname_domain(test2[i]));
#        }   
#    }

event zeek_init()
    {
    Input::add_table([$source=@DIR+"/nets.in",
        $idx=t_ips, $val=t_name, $name="nets", $destination=nets,
        $mode=Input::REREAD]);
    Input::add_table([$source=@DIR+"/domains.in",
        $idx=t_domains, $val=t_name, $name="domains", $destination=domains,
        $mode=Input::REREAD]);
    }
