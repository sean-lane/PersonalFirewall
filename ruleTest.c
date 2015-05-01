#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define print_value(x) (x==NULL?"-" : x)

// struct for holding rule information
struct firewall_rule {
	int rule_number;	// bookkeeping to indicate which rule this is
	int block_control;	// 0 for unblock, 1 for block
	int protocol;		// 0 all, 1 icmp, 6 tcp, 17 udp
	int port_number;	// blocks this particular port
	int ip_address;		// block this ip address (unsure of best way to parse this)
	
	struct firewall_rule* prev_rule;	// access to previous rule
	struct firewall_rule* next_rule;	// access to next rule (just iterate like linked list)

} *fw_tail, *fw_head, *fw_current;

char ruleList[1000] = { 0 };

// function to help print out the rules
char* Print_Rules() {
	// iterate through rule list, searching for rule number
	fw_current = fw_head;

	char string[50] = {0};

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
	printf("rules: %s\n", ruleList);
	return ruleList;
}

// function to add firewall rule (and init rule list if need be)
int Add_Rule(int blockControl, int proto, int portNumber, int ipAddress) {
	
	// first check and see if we have a previous list
	if (fw_head == NULL) {
		// create list head if not
		fw_head = malloc(sizeof(struct firewall_rule));
		
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
		fw_current = malloc(sizeof(struct firewall_rule));
		
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

	printf("New Firewall rule #%d created.\n", fw_current->rule_number);
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
					free(fw_current);
				}
				else {
					free(fw_current);
					fw_current = fw_head = fw_tail = NULL;
				}
			}
			else if (fw_current == fw_tail) {
				// if we get past above condition, head =/= tail
				// to delete tail then, just set it back one reference on list
				fw_tail = fw_tail->prev_rule;
				free(fw_current);
			}
			else {
				// we must be deleting an intermediate entry
				fw_current->prev_rule->next_rule = fw_current->next_rule;
				fw_current->next_rule->prev_rule = fw_current->prev_rule;
				
				free(fw_current);
			}

			// reset fw_current (can be null)
			fw_current = fw_head;
			
			printf("Firewall Rule #%d deleted. \n", ruleNumber);
			return 0;
		}
		else {
			// iterate list if we aren't at end
			fw_current = fw_current->next_rule;
		}
	}

	// if we made it here, nothing was deleted
	printf("Invalid rule deletion attempted. Rule #%d doesn't exist. \n", ruleNumber);
	
	// return failure
	return -1;
}

void main() {
	int rule_number = Add_Rule(1, 0, 80, 192);
	int rule_number2 = Add_Rule (1, 1, 120, 100);

	Print_Rules();

	Remove_Rule(rule_number);
	Remove_Rule(rule_number2);
}

