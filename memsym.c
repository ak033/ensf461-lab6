#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define TRUE 1
#define FALSE 0
#define MAX_PROCESSES 4
#define TLB_SIZE 8
#define NUM_REGISTERS 8

// Replacement Strategy Enumeration
typedef enum {
    FIFO,
    LRU
} ReplacementStrategy;

// TLB Entry Structure
typedef struct {
    int valid;
    uint32_t vpn;          // Virtual Page Number
    uint32_t pfn;          // Physical Frame Number
    uint32_t timestamp;    // Timestamp for replacement strategy
    int pid;               // Process ID
} TLBEntry;

// Page Table Entry Structure
typedef struct {
    int valid;
    uint32_t pfn;
} PageTableEntry;

// Page Table Structure
typedef struct {
    PageTableEntry* entries; // Pointer to an array of PageTableEntry
} PageTable;

// Memory Simulator Structure
typedef struct {
    TLBEntry tlb[TLB_SIZE];                     // TLB entries
    PageTable* page_tables[MAX_PROCESSES];      // Page tables for each process
    uint32_t* physical_memory;                   // Physical memory
    int define_called;                           // Flag to check if define has been called
    int off, pfn_bits, vpn_bits;                 // Memory parameters
    int current_pid;                             // Current Process ID
    uint32_t registers[MAX_PROCESSES][NUM_REGISTERS]; // Registers for each process
} MemorySimulator;

// Global Variables
MemorySimulator simulator;
ReplacementStrategy replacement_strategy;
uint32_t global_timestamp = 0;

// Output file
FILE* output_file;

// Function to tokenize input line
char** tokenize_input(char* input) {
    char** tokens = NULL;
    char* token = strtok(input, " ");
    int num_tokens = 0;

    while (token != NULL) {
        num_tokens++;
        tokens = realloc(tokens, num_tokens * sizeof(char*));
        tokens[num_tokens - 1] = malloc(strlen(token) + 1);
        strcpy(tokens[num_tokens - 1], token);
        token = strtok(NULL, " ");
    }

    tokens = realloc(tokens, (num_tokens + 1) * sizeof(char*));
    tokens[num_tokens] = NULL; // Null-terminate the tokens

    return tokens;
}

// Function to add an entry to the TLB with replacement strategy (no logging)
void add_to_tlb(uint32_t vpn, uint32_t pfn, int pid) {
    int i;
    // Check if VPN is already in TLB and update it
    for (i = 0; i < TLB_SIZE; i++) {
        if (simulator.tlb[i].valid && simulator.tlb[i].pid == pid && simulator.tlb[i].vpn == vpn) {
            simulator.tlb[i].pfn = pfn;
            simulator.tlb[i].timestamp = global_timestamp++;
            return;
        }
    }

    // Look for an empty slot
    for (i = 0; i < TLB_SIZE; i++) {
        if (!simulator.tlb[i].valid) {
            simulator.tlb[i].valid = TRUE;
            simulator.tlb[i].vpn = vpn;
            simulator.tlb[i].pfn = pfn;
            simulator.tlb[i].timestamp = global_timestamp++;
            simulator.tlb[i].pid = pid;
            return;
        }
    }

    // If TLB is full, apply replacement strategy
    int replace_index = 0;
    uint32_t selected_timestamp = simulator.tlb[0].timestamp;

    for (i = 1; i < TLB_SIZE; i++) {
        if (replacement_strategy == FIFO) {
            if (simulator.tlb[i].timestamp < selected_timestamp) {
                selected_timestamp = simulator.tlb[i].timestamp;
                replace_index = i;
            }
        } else if (replacement_strategy == LRU) {
            if (simulator.tlb[i].timestamp < selected_timestamp) {
                selected_timestamp = simulator.tlb[i].timestamp;
                replace_index = i;
            }
        }
    }

    // Replace the selected TLB entry
    simulator.tlb[replace_index].vpn = vpn;
    simulator.tlb[replace_index].pfn = pfn;
    simulator.tlb[replace_index].timestamp = global_timestamp++;
    simulator.tlb[replace_index].pid = pid;
}

// Function to lookup TLB
int lookup_tlb(uint32_t vpn, int pid, uint32_t* pfn, int* tlb_index) {
    for (int i = 0; i < TLB_SIZE; i++) {
        if (simulator.tlb[i].valid && simulator.tlb[i].pid == pid && simulator.tlb[i].vpn == vpn) {
            *pfn = simulator.tlb[i].pfn;
            *tlb_index = i;
            // Update timestamp for LRU
            if (replacement_strategy == LRU) {
                simulator.tlb[i].timestamp = global_timestamp++;
            }
            return TRUE; // TLB Hit
        }
    }
    return FALSE; // TLB Miss
}

// Define function
void define(int off, int pfn_bits, int vpn_bits) {
    if (simulator.physical_memory != NULL) {
        fprintf(output_file, "Error: multiple calls to define in the same trace\n");
        exit(EXIT_FAILURE);
    }
    simulator.off = off;
    simulator.pfn_bits = pfn_bits;
    simulator.vpn_bits = vpn_bits;

    // Calculate physical memory size: 2^(off + pfn_bits)
    simulator.physical_memory = calloc((1 << (off + pfn_bits)), sizeof(uint32_t));
    if (simulator.physical_memory == NULL) {
        fprintf(stderr, "Error allocating physical memory\n");
        exit(EXIT_FAILURE);
    }

    // Initialize TLB
    for (int i = 0; i < TLB_SIZE; i++) {
        simulator.tlb[i].valid = FALSE;
        simulator.tlb[i].pid = -1;
        simulator.tlb[i].vpn = 0;
        simulator.tlb[i].pfn = 0;
        simulator.tlb[i].timestamp = 0;
    }

    // Initialize page tables for each process
    for (int i = 0; i < MAX_PROCESSES; i++) {
        simulator.page_tables[i] = malloc(sizeof(PageTable));
        if (simulator.page_tables[i] == NULL) {
            fprintf(stderr, "Error allocating page table for process %d\n", i);
            exit(EXIT_FAILURE);
        }
        simulator.page_tables[i]->entries = calloc((1 << vpn_bits), sizeof(PageTableEntry));
        if (simulator.page_tables[i]->entries == NULL) {
            fprintf(stderr, "Error allocating page table entries for process %d\n", i);
            exit(EXIT_FAILURE);
        }
        for (int j = 0; j < (1 << vpn_bits); j++) {
            simulator.page_tables[i]->entries[j].valid = FALSE;
            simulator.page_tables[i]->entries[j].pfn = 0;
        }
        // Initialize registers for each process
        for (int k = 0; k < NUM_REGISTERS; k++) {
            simulator.registers[i][k] = 0;
        }
    }

    fprintf(output_file, "Current PID: %d. Memory instantiation complete. OFF bits: %d. PFN bits: %d. VPN bits: %d\n", 
            simulator.current_pid, off, pfn_bits, vpn_bits);
}

// Context switch function
void ctxswitch(int pid) {
    if (pid < 0 || pid >= MAX_PROCESSES) {
        fprintf(output_file, "Current PID: %d. Invalid context switch to process %d\n", simulator.current_pid, pid);
        exit(EXIT_FAILURE);
    }
    simulator.current_pid = pid;
    fprintf(output_file, "Current PID: %d. Switched execution context to process: %d\n", simulator.current_pid, pid);
}

// Load immediate value into register
void load_immediate(int reg, int value) {
    if (reg < 0 || reg >= NUM_REGISTERS) {
        fprintf(output_file, "Current PID: %d. Error: invalid register operand r%d\n", simulator.current_pid, reg);
        return;
    }
    simulator.registers[simulator.current_pid][reg] = value; // Load immediate value into register
    fprintf(output_file, "Current PID: %d. Loaded immediate %d into register r%d\n", simulator.current_pid, value, reg);
}

// Load value from memory into register
void load_address(int address, int reg) {
    if (reg < 0 || reg >= NUM_REGISTERS) {
        fprintf(output_file, "Current PID: %d. Error: invalid register operand r%d\n", simulator.current_pid, reg);
        return;
    }

    // Calculate VPN and offset
    uint32_t vpn = address >> simulator.off;
    uint32_t offset = address & ((1 << simulator.off) - 1);

    uint32_t pfn;
    int tlb_index;
    int hit = lookup_tlb(vpn, simulator.current_pid, &pfn, &tlb_index);

    if (hit) {
        // TLB Hit
        fprintf(output_file, "Current PID: %d. Translating. Lookup for VPN %u hit in TLB entry %d. PFN is %u\n",
                simulator.current_pid, vpn, tlb_index, pfn);
    } else {
        // TLB Miss - Look up the page table
        if (simulator.page_tables[simulator.current_pid]->entries[vpn].valid) {
            pfn = simulator.page_tables[simulator.current_pid]->entries[vpn].pfn;
            fprintf(output_file, "Current PID: %d. Translating. Successfully mapped VPN %u to PFN %u\n",
                    simulator.current_pid, vpn, pfn);
            // Add to TLB
            add_to_tlb(vpn, pfn, simulator.current_pid);
        } else {
            fprintf(output_file, "Current PID: %d. Translating. Translation for VPN %u not found in page table\n",
                    simulator.current_pid, vpn);
            exit(EXIT_FAILURE); // Terminate execution
        }
    }

    // Load the value from physical memory into the register
    uint32_t physical_address = (pfn << simulator.off) | offset;
    simulator.registers[simulator.current_pid][reg] = simulator.physical_memory[physical_address];
    fprintf(output_file, "Current PID: %d. Loaded value of location %u (%u) into register r%d\n",
            simulator.current_pid, address, simulator.physical_memory[physical_address], reg);
}

// Store value from register into memory
void store(int address, int reg) {
    if (reg < 0 || reg >= NUM_REGISTERS) {
        fprintf(output_file, "Current PID: %d. Error: invalid register operand r%d\n", simulator.current_pid, reg);
        return;
    }

    // Calculate VPN and offset
    uint32_t vpn = address >> simulator.off;
    uint32_t offset = address & ((1 << simulator.off) - 1);

    uint32_t pfn;
    int tlb_index;
    int hit = lookup_tlb(vpn, simulator.current_pid, &pfn, &tlb_index);

    if (hit) {
        // TLB Hit
        fprintf(output_file, "Current PID: %d. Translating. Lookup for VPN %u hit in TLB entry %d. PFN is %u\n",
                simulator.current_pid, vpn, tlb_index, pfn);
    } else {
        // TLB Miss - Look up the page table
        if (simulator.page_tables[simulator.current_pid]->entries[vpn].valid) {
            pfn = simulator.page_tables[simulator.current_pid]->entries[vpn].pfn;
            fprintf(output_file, "Current PID: %d. Translating. Successfully mapped VPN %u to PFN %u\n",
                    simulator.current_pid, vpn, pfn);
            // Add to TLB
            add_to_tlb(vpn, pfn, simulator.current_pid);
        } else {
            fprintf(output_file, "Current PID: %d. Translating. Translation for VPN %u not found in page table\n",
                    simulator.current_pid, vpn);
            exit(EXIT_FAILURE); // Terminate execution
        }
    }

    // Store the value in physical memory
    uint32_t physical_address = (pfn << simulator.off) | offset;
    simulator.physical_memory[physical_address] = simulator.registers[simulator.current_pid][reg];
    fprintf(output_file, "Current PID: %d. Stored value of register r%d (%d) into location %u\n",
            simulator.current_pid, reg, simulator.registers[simulator.current_pid][reg], address);
}

// Add function (e.g., add r1 and r2, store in r1)
void add_regs() {
    // Perform addition: r1 = r1 + r2
    int reg1 = 1;
    int reg2 = 2;
    int reg1_value = simulator.registers[simulator.current_pid][reg1];
    int reg2_value = simulator.registers[simulator.current_pid][reg2];
    simulator.registers[simulator.current_pid][reg1] = reg1_value + reg2_value; // Update r1

    // Output the result of the addition
    fprintf(output_file, "Current PID: %d. Added contents of registers r1 (%d) and r2 (%d). Result: %d\n",
            simulator.current_pid, reg1_value, reg2_value, simulator.registers[simulator.current_pid][reg1]);
}

// Map function
void map_vpn_pfn(int vpn, int pfn) {
    if (vpn < 0 || vpn >= (1 << simulator.vpn_bits)) {
        fprintf(output_file, "Current PID: %d. Error: invalid virtual page number %d\n", simulator.current_pid, vpn);
        return;
    }
    
    if (simulator.page_tables[simulator.current_pid]->entries[vpn].valid) {
        fprintf(output_file, "Current PID: %d. Warning: VPN %d is already mapped\n", simulator.current_pid, vpn);
    }
    
    simulator.page_tables[simulator.current_pid]->entries[vpn].valid = TRUE;
    simulator.page_tables[simulator.current_pid]->entries[vpn].pfn = pfn;

    fprintf(output_file, "Current PID: %d. Mapped virtual page number %d to physical frame number %d\n", 
            simulator.current_pid, vpn, pfn);
    
    // Add the mapping to the TLB without logging
    add_to_tlb(vpn, pfn, simulator.current_pid);
}

// Unmap function
void unmap_vpn(int vpn) {
    if (vpn < 0 || vpn >= (1 << simulator.vpn_bits)) {
        fprintf(output_file, "Current PID: %d. Error: invalid virtual page number %d\n", simulator.current_pid, vpn);
        return;
    }

    PageTableEntry* entry = &simulator.page_tables[simulator.current_pid]->entries[vpn];

    if (!entry->valid) {
        fprintf(output_file, "Current PID: %d. Error: Attempt to unmap an already unmapped virtual page number %d\n", simulator.current_pid, vpn);
        return;
    }

    entry->valid = FALSE; // Mark the entry as invalid
    entry->pfn = 0;       // Reset PFN if needed
    fprintf(output_file, "Current PID: %d. Unmapped virtual page number %d\n", simulator.current_pid, vpn);

    // Invalidate the corresponding TLB entry if present (no logging)
    for (int i = 0; i < TLB_SIZE; i++) {
        if (simulator.tlb[i].valid && simulator.tlb[i].pid == simulator.current_pid && simulator.tlb[i].vpn == vpn) {
            simulator.tlb[i].valid = FALSE;
            simulator.tlb[i].pid = -1;
            // No logging here to match expected output
            break; // Assuming only one TLB entry per VPN
        }
    }
}

// Function to free allocated memory
void cleanup() {
    for (int i = 0; i < MAX_PROCESSES; i++) {
        free(simulator.page_tables[i]->entries);
        free(simulator.page_tables[i]);
    }
    free(simulator.physical_memory);
}

// Main function
int main(int argc, char* argv[]) {
    simulator.current_pid = 0; 
    const char usage[] = "Usage: memsym.out <strategy> <input trace> <output trace>\n";
    char* input_trace;
    char* output_trace;
    char buffer[1024];
    simulator.define_called = FALSE;

    // Parse command line arguments
    if (argc != 4) {
        printf("%s", usage);
        return 1;
    }

    // Set the replacement strategy
    if (strcmp(argv[1], "FIFO") == 0) {
        replacement_strategy = FIFO;
    } else if (strcmp(argv[1], "LRU") == 0) {
        replacement_strategy = LRU;
    } else {
        fprintf(stderr, "Unknown replacement strategy: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    input_trace = argv[2];
    output_trace = argv[3];

    // Open input and output files
    FILE* input_file = fopen(input_trace, "r");
    if (!input_file) {
        perror("Error opening input trace file");
        return EXIT_FAILURE;
    }

    output_file = fopen(output_trace, "w");  
    if (!output_file) {
        perror("Error opening output trace file");
        fclose(input_file);
        return EXIT_FAILURE;
    }

    // Check for empty trace then return for other tests to be checked
    fseek(input_file, 0, SEEK_END);
    if (ftell(input_file) == 0) {
        fclose(input_file);
        fclose(output_file);
        return 0;
    }
    rewind(input_file); 

    while (fgets(buffer, sizeof(buffer), input_file)) {
        // Remove endline character
        buffer[strcspn(buffer, "\n")] = '\0'; // This is safer
        if (buffer[0] == '%') {
            continue; // Ignore comments
        }
        char** tokens = tokenize_input(buffer);

        // Implement memory simulator commands
        if (strcmp(tokens[0], "define") == 0) {
            if (simulator.define_called) {
                fprintf(output_file, "Current PID: %d. Error: multiple calls to define in the same trace\n", simulator.current_pid);
                exit(EXIT_FAILURE);
            }

            if (tokens[1] == NULL || tokens[2] == NULL || tokens[3] == NULL) {
                fprintf(stderr, "Error: Missing arguments for define.\n");
                exit(EXIT_FAILURE);
            }

            int off = atoi(tokens[1]);
            int pfn_bits = atoi(tokens[2]);
            int vpn_bits = atoi(tokens[3]);
            define(off, pfn_bits, vpn_bits);
            simulator.define_called = TRUE;
        } else if (!simulator.define_called) {
            fprintf(output_file, "Current PID: %d. Error: attempt to execute instruction before define\n", simulator.current_pid);
            exit(EXIT_FAILURE);
        } else if (strcmp(tokens[0], "ctxswitch") == 0) {
            if (tokens[1] == NULL) {
                fprintf(stderr, "Error: Missing argument for ctxswitch.\n");
                exit(EXIT_FAILURE);
            }
            int new_pid = atoi(tokens[1]);
            ctxswitch(new_pid);
        } else if (strcmp(tokens[0], "load") == 0) {
            if (tokens[1] == NULL || tokens[2] == NULL) {
                fprintf(stderr, "Error: Missing arguments for load.\n");
                exit(EXIT_FAILURE);
            }
            // Determine if it's load immediate or load from address
            if (tokens[2][0] == '#') {
                // Load immediate
                int reg = atoi(tokens[1] + 1); // Assume reg is in the form of r1, r2...
                int value = atoi(tokens[2] + 1); // Skip the '#' in '#value'
                load_immediate(reg, value);
            } else {
                // Load from address
                int reg = atoi(tokens[1] + 1); // Assume reg is in the form of r1, r2...
                int address = atoi(tokens[2]);
                load_address(address, reg);
            }
        } else if (strcmp(tokens[0], "add") == 0) {
            add_regs();
        } else if (strcmp(tokens[0], "map") == 0) {
            if (tokens[1] == NULL || tokens[2] == NULL) {
                fprintf(stderr, "Error: Missing arguments for map.\n");
                exit(EXIT_FAILURE);
            }
            int vpn = atoi(tokens[1]);
            int pfn = atoi(tokens[2]);
            map_vpn_pfn(vpn, pfn);
        } else if (strcmp(tokens[0], "unmap") == 0) {
            if (tokens[1] == NULL) {
                fprintf(stderr, "Error: Missing argument for unmap.\n");
                exit(EXIT_FAILURE);
            }
            int vpn = atoi(tokens[1]);
            unmap_vpn(vpn);
        } else if (strcmp(tokens[0], "store") == 0) {
            if (tokens[1] == NULL || tokens[2] == NULL) {
                fprintf(stderr, "Error: Missing arguments for store.\n");
                exit(EXIT_FAILURE);
            }
            int address = atoi(tokens[1]);
            int reg = atoi(tokens[2] + 1); // Assume reg is in the form of r1, r2...
            store(address, reg);
        } else {
            // Handle any unknown command case if needed
            fprintf(output_file, "Current PID: %d. Unknown command: %s\n", simulator.current_pid, tokens[0]);
        }

        // Deallocate tokens
        for (int i = 0; tokens[i] != NULL; i++) {
            free(tokens[i]);
        }
        free(tokens);
    }

    // Clean up
    cleanup();

    // Close input and output files
    fclose(input_file);
    fclose(output_file);

    return 0;
}
