module EffectiveName;

@load ./effective-tld.zeek

export {
    # Define a record type for the effective names
    type Effective: record {
        application: string &optional;
        tld: string &optional;
    };

    ## This function can strip domain portions from domain names efficiently.
    ##
    ## domain: The domain to strip domain portions from.
    ## depth: The number of domain portions that you would like to keep.
    ##
    ## Returns: The domain with the requested number of domain components remaining.
    global zone_by_depth: function(domain: string, depth: count): string;

    ## This function returns an Effective record that contains the effectives
    ## application name and tld for a domain
    ##
    ## x.y.z.googleapis.com -> z / googleapis.com
    ## www.googleapis.com -> z / googleapis / com
    global ename: function(domain: string): Effective;
}


# These are used to match the depth of domain components desired since
# patterns can't (and probably shouldn't be) compiled dynamically).
const tld_extraction_suffixes: table[count] of pattern = {
    [1] = /\.[^\.]+$/,
    [2] = /\.[^\.]+\.[^\.]+$/,
    [3] = /\.[^\.]+\.[^\.]+\.[^\.]+$/,
    [4] = /\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+$/,
    [5] = /\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+$/,
    [6] = /\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+$/,
    [7] = /\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+$/,
};

function zone_by_depth(domain: string, depth: count): string {
    # If the requested depth is not defined, return the original domain
    if ( depth !in tld_extraction_suffixes )
        return domain;

    # Find the last the longer tld
    local result = find_last(domain, tld_extraction_suffixes[depth]);
    if ( result == "" )
        return domain;
    return result[1:];
}

function ename(domain: string): Effective  {
    local app: string;
    local depth=1;

    # Define the depth of the effective tld by checking the publicsuffix regexes
    if ( effective_tlds_5th_level in domain )
        depth=5;
    else if ( effective_tlds_4th_level in domain )
        depth=4;
    else if ( effective_tlds_3rd_level in domain )
        depth=3;
    else if ( effective_tlds_2nd_level in domain )
        depth=2;

    # Get the effective tld
    local tld = zone_by_depth(domain, depth);
    if (domain == tld) # typically internal domains having depth 1
        app = domain;
    else {
        # Identify the effective application
        local name = domain[0:|domain|-|tld|-1];
        app = gsub(name, /.+\./, "");
        if ( app == "www") { # Typically www.googleapis.com
            --depth;
            tld = zone_by_depth(domain, depth);
            name = domain[0:|domain|-|tld|-1];
            app = gsub(name, /.+\./, "");
        }
    }
    return Effective($application = app,
    $tld = tld);
}
	
#event zeek_init()
#	{
#	local domains = vector("blah.www.google.com", "test.googleapis.com", "www.googleapis.com", "googleapis.com", "x.y.z.google.com", "www.easa.eu.int", "com");
#	for ( i in domains )
#		{
#		local result = ename(domains[i]);
#		print fmt("Original: %s", domains[i]);
#		print fmt("    Application: %s", result$application);
#		print fmt("    TLD: %s", result$tld);
#		}
#	}
