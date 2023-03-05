
module KnownApp;

# Define a record to represent a node in the radix tree
type Node: record {
    is_leaf: bool;  # Boolean flag indicating whether this node represents the end of a string
    name: string &optional;
    children: table[count] of count;  # Table mapping characters to child nodes
};

# Define a record to represent the entire radix tree
type RadixTree: record {
    nodes: vector of Node;  # vector of nodes in the tree
    root: count;  # index of the root node in the 'nodes' array
};

export {
    # Define a record to represent the known application
    type app: record {
        exist: bool;  # True if the app was found
        name: string &optional;
    };

    global search_ip: function(key: addr): app;
}

# Define records to identify the column in the source file
type t_ip: record {
    ip: subnet;
};
type t_name: record {
    name: string;
};


global nets: table[subnet] of t_name; # Table to store the content from the source file

# Function to get the value of the nth bit in the value
function bit_value(value: count, n: count): count {
    local divisor: count = 1;
    local i: count = 1;
    while ( i <= n ) {
        divisor = 2 * divisor;
        i += 1;
    }
    return ((value / divisor) & 1);
}

# Function to create a new node with the specified leaf status and an empty children table
function new_node(is_leaf: bool): Node {
    local t: table[count] of count = {};
    local node: Node = [$is_leaf=is_leaf, $children=t];
    return node;
}

# Function to initialize the radix tree
function init_tree(): RadixTree
    {
    local v : vector of Node = vector();
    local tree: RadixTree = [$nodes=v, $root=0];
    tree$nodes += new_node(F);
    return tree;
}

global tree = init_tree(); # Intialize the radix tree

# Function to insert a new subnet into the tree
function insert_subnet(key: subnet, name: string) {
    local mask : count = subnet_width(key);
    local net : count = addr_to_counts(subnet_to_addr(key))[0]; # Convert the subnet to count
    local node: count = tree$root; # Start at the root node

    # Traverse the tree bit-by-bit, creating new child nodes as necessary
    local bit: count;
    local i = 32;
    while ( i != 32-mask ) { # Ignore the bits out of the mask
        bit = bit_value(net, i-1);
        local child: count;
        if (bit !in tree$nodes[node]$children) { # Create a new child node if it doesn't exist yet
            child = |tree$nodes|;
            tree$nodes += new_node(F);
            tree$nodes[node]$children[bit] = child; # Set the current node's child for the current bit
        }
        else # If the current node already has a child for the current bit, use it
            child = tree$nodes[node]$children[bit];
        node = child;  # Continue traversing the tree with the child node
        i -= 1;

    }
    tree$nodes[node]$is_leaf = T; # Set the flag on the last node to indicate that it represents the end of a string
    tree$nodes[node]$name = name;
}

# Function to search for an addr in the tree
function search_ip(key: addr): app {
    local net : count = addr_to_counts(key)[0];
    local result: app;
    local node: count = tree$root;  # Start at the root node

    # Traverse the tree bit-by-bit
    local bit: count;
    local i: count = 32;
    while ( i != 0 ) {
        bit = bit_value(net, i-1);
        if (tree$nodes[node]$is_leaf == T) { # If we've reached a leaf node, the net is in the tree
            local appname = tree$nodes[node]$name;
            local output = "";
            local tab = split_string(appname, /_/);
            for (i in tab)
                output += tab[i][0] + to_lower(tab[i][1:]); # AMAZON_AWS => AmazonAws
            result = [$exist=T, $name=output];
            return result;
        }
        if (bit !in tree$nodes[node]$children) { # If there's no child node for this bit, the net isn't in the tree
            result = [$exist=F, $name=""];
            return result;
        }
        node = tree$nodes[node]$children[bit]; # Move to the next node in the tree
        i -= 1;
    }
    result = [$exist=F, $name=""]; # This should not happen
    return result; # This should not happen
}


event Input::end_of_data(name: string, source: string) {
    if ( "nets.in" in source ) {
        print fmt("%d nets extracted from the source file", |nets|);
        for ( row in nets )
            insert_subnet(row, nets[row]$name);
#        local test: vector of addr = vector(192.168.1.1, 101.33.128.10);
#        for ( i in test ) {
#            print fmt("IP: %s", test[i]);
#            print fmt("  Known: %s", search_ip(test[i]));
#        }
    }
}

event zeek_init() {
    Input::add_table([$source=@DIR+"/nets.in",
        $idx=t_ip, $val=t_name, $name="nets", $destination=nets,
        $mode=Input::REREAD]);
}

