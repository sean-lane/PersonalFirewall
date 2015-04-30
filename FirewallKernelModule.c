#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/string.h>

#include <linux/init.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <asm/types.h>
#include <linux/netlink.h>

#define NETLINK_USER 31

struct sock *nl_sk = NULL;

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Personal Firewall");
MODULE_AUTHOR("Sean Lane and Brad Moran");

// struct for socket buffer
struct sk_buff *sock_buff;

// structs for various headers
struct iphdr *ip_header;
struct udphdr *udp_header;
struct tcphdr *tcp_header;
struct icmphdr *icmp_header;



// Command structure for setting up a netfilter hook
static struct nf_hook_ops nfho;

// struct for holding rule information
struct firewall_rule {
	int rule_number;	// bookkeeping to indicate which rule this is
	int block_control;	// 0 for unblock, 1 for block
	int port_number;	// blocks this particular port
	int ip_address;		// block this ip address (unsure of best way to parse this)
	
	struct firewall_rule* prev_rule;	// access to previous rule
	struct firewall_rule* next_rule;	// access to next rule (just iterate like linked list)

} *fw_tail, *fw_head, *fw_current;

// This function designates what to do if a packet meets the criteria in nf_hook_ops
unsigned int hook_func(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff*))
{
	// acquire socket buffer
	sock_buff = skb;

	// acquire ip header of packet
	ip_header = (struct iphdr *)skb_network_header(sock_buff);
       
	// make sure we have something valid in the buffer, otherwise accept
        if(!sock_buff) { 
		return NF_ACCEPT;
	}
 	
	// check ip header protocol number: 1 for ICMP, 6 for TCP, 17 for UDP
	// http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
	if (ip_header->protocol == 1) {
		// grab ICMP header
		icmp_header = (struct icmphdr *)skb_transport_header(sock_buff);
		
		printk(KERN_INFO "ICMP packet dropped! \n");   
                return NF_ACCEPT;
	}

	// check if tcp
	else if (ip_header->protocol == 6) {
		// grab TCP header
		tcp_header = (struct tcphdr *)skb_transport_header(sock_buff);

		printk(KERN_INFO "TCP packet dropped! \n");   
                return NF_ACCEPT;
	}

	// check if UDP
	else if (ip_header->protocol == 17) {
		// if so, grab UDP header (see udp.h)
                udp_header = (struct udphdr *)skb_transport_header(sock_buff);
 
                printk(KERN_INFO "UDP packet dropped! \n");   
                return NF_ACCEPT;
        }

	else {
		// tell kernel that we dropped a strange packet
		printk(KERN_INFO "Other packet Dropped! \n");

		// drop the packet
		return NF_ACCEPT;
	}
}

// function to add firewall rule (and init rule list if need be)
int Add_Rule(int blockControl, int portNumber, int ipAddress) {
	
	// first check and see if we have a previous list
	if (fw_head == NULL) {
		// create list head if not
		fw_head = vmalloc(sizeof(struct firewall_rule));
		
		fw_tail = fw_head;
		fw_current = fw_head;
		
		// insert new rule here at head
		fw_head->rule_number = 1;
		fw_head->block_control = blockControl;
		fw_head->port_number = portNumber;
		fw_head->ip_address = ipAddress;

		fw_head->prev_rule = NULL;
		fw_head->next_rule = NULL;
	}

	// otherwise, insert new rule at end of list
	else {
		fw_current = vmalloc(sizeof(struct firewall_rule));
		
		// set info for new rule
		fw_current->rule_number = (fw_tail->rule_number + 1);
		fw_current->block_control = blockControl;
		fw_current->port_number = portNumber;
		fw_current->ip_address = ipAddress;

		// assemble list
		fw_current->prev_rule = fw_tail;
		fw_tail->next_rule = fw_current;

		// update tail
		fw_tail = fw_current;
	}

	printk(KERN_INFO "New Firewall rule #%d created.\n", fw_current->rule_number);
	return fw_current->rule_number;
}

// function to remove firewall rule
int Remove_Rule(int ruleNumber) {
	// iterate through rule list, searching for rule number
	fw_current = fw_head;
	
	// while we aren't at the end of the list...
	while (fw_current != NULL) {
		
		// check if rule numbers match
		if (fw_current->rule_number == ruleNumber) {
			// if so, delete this rule from list depending on if it is the
			// head, tail, or in-between
			if (fw_current == fw_head) {
				// if deleting head, check if there is more than one entry
				if (fw_current->next_rule != NULL) {
					fw_head = fw_current->next_rule;
					vfree(fw_current);
				}
				else {
					vfree(fw_current);
					fw_current = fw_head = fw_tail = NULL;
				}
			}
			else if (fw_current == fw_tail) {
				// if we get past above condition, head =/= tail
				// to delete tail then, just set it back one reference on list
				fw_tail = fw_tail->prev_rule;
				vfree(fw_current);
			}
			else {
				// we must be deleting an intermediate entry
				fw_current->prev_rule->next_rule = fw_current->next_rule;
				fw_current->next_rule->prev_rule = fw_current->prev_rule;
				
				vfree(fw_current);
			}

			// reset fw_current (can be null)
			fw_current = fw_head;
			
			printk(KERN_INFO "Firewall Rule #%d deleted. \n", ruleNumber);
			return 0;
		}
		else {
			// iterate list if we aren't at end
			fw_current = fw_current->next_rule;
		}
	}

	// if we made it here, nothing was deleted
	printk(KERN_INFO "Invalid rule deletion attempted. Rule #%d doesn't exist. \n", ruleNumber);
	
	// return failure
	return -1;
}

static void receive_msg(struct sk_buff *skb) 
{

	struct nlmsghdr *nh;
	int pid;
	struct sk_buff *skb_out;
	int msg_size;
	char *msg = "Hello from kernel";
	int res;
	
	printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

	msg_size = strlen (msg);

	nh = (struct nlmsghdr *)skb->data;
	printk(KERN_INFO "Netlink recceived msg payload: %s\n", (char *)nlmsg_data(nh));
	// determine what command is passed
        char *first = strchr((char *)nlmsg_data(nh), ' ');
        printk(KERN_INFO "first: %s\n", first);
        char *command;
        strncpy(command, (char *)nlmsg_data(nh), (int)first);
        printk(KERN_INFO "command: %s\n", command);

	/*if(strcmp(command, "NEW") {
		parse other info from userspace string
		AddRule(...);
		return rule added message
	} else if(strcmp(command, "DELETE") {
		parse rule number to delete
		DeleteRule(rule number);
		return rule deleted message
	} else if(strcmp(command, "PRINT") {
		return list of rules
	} else {
		return command not recognized message
	}
	*/
	
	pid = nh->nlmsg_pid;
	
	skb_out = nlmsg_new(msg_size, 0);

	if(!skb_out) {
		printk(KERN_ERR "Failed to allocate new skb\n");
		return;
	}
	nh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
	NETLINK_CB(skb_out).dst_group = 0;
	strncpy(nlmsg_data(nh), msg, msg_size);

	res = nlmsg_unicast(nl_sk, skb_out, pid);

	if(res < 0) {
		printk(KERN_INFO "Error while sending back to user\n");
	}
}

// Function to initialize firewall hooks
static int Start_Firewall(void)
{
	// Attempt to create socket
	printk(KERN_INFO "Attempting to create Netlink socket\n");
	
	struct netlink_kernel_cfg cfg = {
		.groups = 1,
                .input = receive_msg,
        };
        nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
	
	if(!nl_sk) {
		printk(KERN_ALERT "Error creating socket.\n");
		return -10;
	}

	printk(KERN_INFO "Netlink socket created.\n");
	
	//function to call when conditions below met
	nfho.hook = hook_func;

	// setup to use the first available netfilter hook (right after packet recieved)
	nfho.hooknum = NF_INET_PRE_ROUTING;

	// want only IPv4 Packets (can expand to IPv6 later)
	nfho.pf = PF_INET;

	// Make our hook highest priority; needs to be to effectively block packets
	nfho.priority = NF_IP_PRI_FIRST;

	// register hook with netfilter
	nf_register_hook(&nfho);

	// return 0 (success)
	printk(KERN_INFO "NF Hook Registered! \n");

	
	
	return 0;
}

// function to clean up firewall data
static void Stop_Firewall(void)
{
	// free socket
	netlink_kernel_release(nl_sk);
	printk(KERN_INFO "Netlink socket released! \n");

	// deregister hook with netfilter
	//nf_unregister_hook(&nfho);
	//printk(KERN_INFO "NF Hook Removed! \n");

	printk(KERN_INFO "Exiting module\n");
}

// set module initialization / cleanup functions
module_init(Start_Firewall);
module_exit(Stop_Firewall);
