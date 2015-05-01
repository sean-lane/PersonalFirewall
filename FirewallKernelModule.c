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
#define print_value(x) (x==NULL?"-" : x)

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

// unique rule numbers
static int ruleNumber = 0;

// Command structure for setting up a netfilter hook
static struct nf_hook_ops nfho;

// struct for holding rule information
struct firewall_rule {
	int rule_number;	// bookkeeping to indicate which rule this is
	int block_control;	// 0 for unblock, 1 for block
	int protocol;		// 0 all, 1 icmp, 6 tcp, 17 udp
	unsigned int port_number;	// blocks this particular port
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
       
	unsigned int sport, dport;

	// make sure we have something valid in the buffer, otherwise accept
        if(!sock_buff) { 
		return NF_ACCEPT;
	}

	// check if we need to block this packet with rule list by iterating through whole list
	fw_current = fw_head;
	while (fw_current != NULL) {
		
		// check if this is a blocking rule
		if(fw_current->block_control == 1) {

			// check if we are blocking this protocol
			if(ip_header->protocol == fw_current->protocol) {
				printk(KERN_INFO "Packet dropped from Firewall Rule %d: Protocol %d blocked.\n", fw_current->rule_number, ip_header->protocol);
				return NF_DROP;
			}
			
			// otherwise look at protocol header
			else {

				// check ip header protocol number: 1 for ICMP, 6 for TCP, 17 for UDP. Get header for packet
				// http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
				// check if tcp
				if (ip_header->protocol == 6) {
					// grab TCP header
					//tcp_header = (struct tcphdr *)skb_transport_header(sock_buff);
					tcp_header = (struct tcphdr *)((__u32 *)ip_header +ip_header->ihl);				
					sport = htons((unsigned short int) tcp_header->source);
					dport = htons((unsigned short int) tcp_header->dest);

					if (fw_current->port_number == dport) {
						printk(KERN_INFO "TCP Packet dropped from Firewall Rule %d: Port %d blocked.\n", fw_current->rule_number, fw_current->port_number);
						return NF_DROP;
					}

				}

				// check if UDP
				else if (ip_header->protocol == 17) {
					// if so, grab UDP header (see udp.h)
			                udp_header = (struct udphdr *)((__u32 *)ip_header +ip_header->ihl);
					
					sport = htons((unsigned short int) udp_header->source);
					dport = htons((unsigned short int) udp_header->dest);

					if (fw_current->port_number == dport) {
						printk(KERN_INFO "UDP Packet dropped from Firewall Rule %d: Port %d blocked.\n", fw_current->rule_number, fw_current->port_number);
						return NF_DROP;
					}
			        }
			}
		}
		fw_current = fw_current->next_rule;
	}
	return NF_ACCEPT;
}

// function to add firewall rule (and init rule list if need be)
int Add_Rule(int blockControl, int proto, int portNumber, int ipAddress) {
	
	// first check and see if we have a previous list
	if (fw_head == NULL) {
		// create list head if not
		fw_head = vmalloc(sizeof(struct firewall_rule));
		
		fw_tail = fw_head;
		fw_current = fw_head;
		
		// insert new rule here at head
		fw_head->rule_number = 1;
		fw_head->block_control = blockControl;
		fw_head->protocol = proto;
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
		fw_current->protocol = proto;
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

// function to help print out the rules
char* Print_Rules(void) {
	// iterate through rule list, searching for rule number
	fw_current = fw_head;
	
	char ruleList[1500] = { 0 };

	// Create a list of rules. Each piece of rule is space seperated so
	// use ";" char as delimiter between rules

	// while we aren't at the end of the list...
	while (fw_current != NULL) {
		sprintf(ruleList+ strlen(ruleList), "\nRule Number: %d; ", (fw_current->rule_number));
		sprintf(ruleList+ strlen(ruleList), "Blocking? %d; ", (fw_current->block_control));
		sprintf(ruleList+ strlen(ruleList), "Protocol: %d; ", (fw_current->protocol));
		sprintf(ruleList+ strlen(ruleList), "Port Number %d; ", (fw_current->port_number));
		sprintf(ruleList+ strlen(ruleList), "IP: %d; ", (fw_current->ip_address));	

		fw_current = fw_current->next_rule;
	}
	printk(KERN_INFO "rules: %s\n", ruleList);
}

// function to receive packet from netlink socket
static void receive_msg(struct sk_buff *skb) 
{
	// netlink overhead declarations
	struct nlmsghdr *nh;
	int pid;
	struct sk_buff *skb_out;
	int msg_size;
	char *msg = "Hello from kernel";
	int res;
	
	// command issued by incoming packet
	char *command = kmalloc(sizeof(char[2]), GFP_USER);

		
	printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

	msg_size = strlen (msg);

	nh = (struct nlmsghdr *)skb->data;

	printk(KERN_INFO "Netlink received msg payload: %s\n", (char *)nlmsg_data(nh));
	
	// determine what command is passed
        strncpy(command, (char *)nlmsg_data(nh), 1);
	command[1] = '\0';
        printk(KERN_INFO "command: %s\n", command);

	if(strcmp(command, "1") == 0) {
		int bc = 0;
		int proto = 0;
		int pt = 0;
		int ip = 0; 
		//AddRule(...);
		//return rule added message
		printk(KERN_INFO "command: %s\n", "new");
		char *payload = (char *)nlmsg_data(nh);
	
	
		// parse other info from userspace string
		char *token1 = strsep(&payload, " ");
		char *token2 = strsep(&payload, " ");
		char *token3 = strsep(&payload, " ");
		char *token4 = strsep(&payload, " ");
		char *token5 = strsep(&payload, " ");

/*		printk(KERN_INFO "tokens: %s\n", token1);
		printk(KERN_INFO "tokens: %s\n", token2);
		printk(KERN_INFO "tokens: %s\n", token3);
		printk(KERN_INFO "tokens: %s\n", token4);
		printk(KERN_INFO "tokens: %s\n", token5);
*/
		if(kstrtol(token2, 10, &bc) != 0) {
			printk(KERN_INFO "Could not parse string to int");
		}

		if(kstrtol(token3, 10, &proto) != 0) {
			printk(KERN_INFO "Could not parse string to int");
		}

		if(kstrtol(token4, 10, &pt) != 0) {
			printk(KERN_INFO "Could not parse string to int");
		}

		if(kstrtol(token5, 10, &ip) != 0) {
			printk(KERN_INFO "Could not parse string to int");
		}
		
		printk(KERN_INFO "tokens2int: %d\n", bc);
		printk(KERN_INFO "tokens3int: %d\n", proto);
		printk(KERN_INFO "tokens4int: %d\n", pt);
		printk(KERN_INFO "tokens5int: %d\n", ip);

		Add_Rule(bc, proto, pt, ip);

		pid = nh->nlmsg_pid;
	
		skb_out = nlmsg_new(msg_size, 0);

		if(!skb_out) {
			printk(KERN_ERR "Failed to allocate new skb\n");
			kfree(command);
			return;
		}
		nh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
		NETLINK_CB(skb_out).dst_group = 0;
		strcpy(nlmsg_data(nh), "Added new rule");
	
		res = nlmsg_unicast(nl_sk, skb_out, pid);
		
		kfree(command);
		if(res < 0) {
			printk(KERN_INFO "Error while sending back to user\n");
		}
	
	} else if(strcmp(command, "2") == 0) {
		int deleteRule = 0;
		int success = -1;
		//parse rule number to delete
		//DeleteRule(rule number);
		//return rule deleted message
		printk(KERN_INFO "command: %s\n", "delete");
		char *payload = (char *)nlmsg_data(nh);
		

		char *token1 = strsep(&payload, " ");
		char *token2 = strsep(&payload, " ");

		if(kstrtol(token2, 10, &deleteRule) != 0) {
			printk(KERN_INFO "Could not parse string to int");
		}

		printk(KERN_INFO "tokens2int: %d\n", deleteRule);

		success = Remove_Rule(deleteRule);
	
		pid = nh->nlmsg_pid;
	
		skb_out = nlmsg_new(msg_size, 0);
	
		if(!skb_out) {
			printk(KERN_ERR "Failed to allocate new skb\n");
			kfree(command);
			return;
		}
		nh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
		NETLINK_CB(skb_out).dst_group = 0;

		// check if successful
		if (success = 0) {
			strcpy(nlmsg_data(nh), "Rule deleted");
		}
		else {
			strcpy(nlmsg_data(nh), "Rule does not exist!\n");
		}
	
		res = nlmsg_unicast(nl_sk, skb_out, pid);
		
		kfree(command);
		if(res < 0) {
			printk(KERN_INFO "Error while sending back to user\n");
		}

	} else if(strcmp(command, "3") == 0) {
		//return list of rules
		printk(KERN_INFO "command: %s\n", "print");

		Print_Rules();

		pid = nh->nlmsg_pid;
	
		skb_out = nlmsg_new(msg_size, 0);

		if(!skb_out) {
			printk(KERN_ERR "Failed to allocate new skb\n");
			kfree(command);
			return;
		}
		nh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
		NETLINK_CB(skb_out).dst_group = 0;
		// TODO: send back all of the rules
		strncpy(nlmsg_data(nh), msg, sizeof(msg));

		res = nlmsg_unicast(nl_sk, skb_out, pid);
	
		kfree(command);
		if(res < 0) {
			printk(KERN_INFO "Error while sending back to user\n");
		}
	
	} else {
		//return command not recognized message
		printk(KERN_INFO "command: %s\n", "not recognized");
		pid = nh->nlmsg_pid;
	
		skb_out = nlmsg_new(msg_size, 0);

		if(!skb_out) {
			printk(KERN_ERR "Failed to allocate new skb\n");
			kfree(command);
			return;
		}
		nh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
		NETLINK_CB(skb_out).dst_group = 0;
		strcpy(nlmsg_data(nh), "Command not recognized");

		res = nlmsg_unicast(nl_sk, skb_out, pid);
	
		kfree(command);
		if(res < 0) {
			printk(KERN_INFO "Error while sending back to user\n");
		}

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
	int ruleNum = 0;
	
	// free socket
	netlink_kernel_release(nl_sk);
	printk(KERN_INFO "Netlink socket released! \n");

	// deregister hook with netfilter
	nf_unregister_hook(&nfho);
	printk(KERN_INFO "NF Hook Removed! \n");

	printk(KERN_INFO "Exiting module\n");

	// cleanup rules
	fw_current = fw_head;
	while (fw_current != NULL) {
		ruleNum = fw_current->rule_number;
		fw_current = fw_current->next_rule;
		Remove_Rule(ruleNum);
	}
}

// set module initialization / cleanup functions
module_init(Start_Firewall);
module_exit(Stop_Firewall);
