#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX 50
// === PACKET FILTER SIMULATOR ===

// Submitted by | D. Cayanes | Angelica Paguinto | Data Structures and Algorithm 213 Finals | Instructor Mr. Jaymart Maala

// For colored text output (works on most terminals)
#define RED   "\x1B[31m"
#define GREEN "\x1B[32m"
#define YELLOW "\x1B[33m"
#define RESET "\x1B[0m"

// ---------------------- Packet Definition ----------------------
typedef struct {
    char sourceIP[16];
    int port;
    char type[10];  // TCP or UDP
    int size;       // packet size in bytes
} Packet;

// ---------------------- Queue Definition ----------------------
typedef struct {
    Packet data[MAX];
    int front;
    int rear;
} Queue;

// ---------------------- Stack Definition (for blocked packets) ----------------------
typedef struct {
    Packet data[MAX];
    int top;
} Stack;

// ---------------------- Queue Functions ----------------------
void initQueue(Queue *q) {
    q->front = -1;
    q->rear = -1;
}

int isFullQueue(Queue *q) {
    return q->rear == MAX - 1;
}

int isEmptyQueue(Queue *q) {
    return q->front == -1 || q->front > q->rear;
}

void enqueue(Queue *q, Packet p) {
    if (isFullQueue(q)) {
        printf(RED "Queue is full! Cannot enqueue packet.\n" RESET);
        return;
    }
    if (q->front == -1)
        q->front = 0;
    q->data[++q->rear] = p;
    printf(GREEN "Packet added to queue successfully.\n" RESET);
}

Packet dequeue(Queue *q) {
    Packet temp;
    if (isEmptyQueue(q)) {
        printf(RED "Queue is empty! No packets to process.\n" RESET);
        strcpy(temp.sourceIP, "0.0.0.0");
        temp.port = 0;
        strcpy(temp.type, "NONE");
        temp.size = 0;
        return temp;
    }
    temp = q->data[q->front++];
    if (q->front > q->rear)
        initQueue(q);
    return temp;
}

void displayQueue(Queue *q) {
    if (isEmptyQueue(q)) {
        printf(YELLOW "No packets in queue.\n" RESET);
        return;
    }
    printf("\n--- CURRENT PACKETS IN QUEUE ---\n");
    for (int i = q->front; i <= q->rear; i++) {
        printf("%d) %s | Port: %d | %s | Size: %d bytes\n",
               i - q->front + 1,
               q->data[i].sourceIP,
               q->data[i].port,
               q->data[i].type,
               q->data[i].size);
    }
    printf("---------------------------------\n");
}

// ---------------------- Stack Functions ----------------------
void initStack(Stack *s) {
    s->top = -1;
}

int isFullStack(Stack *s) {
    return s->top == MAX - 1;
}

int isEmptyStack(Stack *s) {
    return s->top == -1;
}

void push(Stack *s, Packet p) {
    if (isFullStack(s)) {
        printf(RED "Blocked packet log is full!\n" RESET);
        return;
    }
    s->data[++s->top] = p;
}

Packet pop(Stack *s) {
    Packet p;
    if (isEmptyStack(s)) {
        strcpy(p.sourceIP, "0.0.0.0");
        p.port = 0;
        strcpy(p.type, "NONE");
        p.size = 0;
        return p;
    }
    return s->data[s->top--];
}

void displayBlocked(Stack *s) {
    if (isEmptyStack(s)) {
        printf(YELLOW "No blocked packets recorded.\n" RESET);
        return;
    }
    printf("\n--- BLOCKED PACKETS (Most recent first) ---\n");
    for (int i = s->top; i >= 0; i--) {
        printf("%d) %s | Port: %d | %s | Size: %d bytes\n",
               s->top - i + 1,
               s->data[i].sourceIP,
               s->data[i].port,
               s->data[i].type,
               s->data[i].size);
    }
    printf("-------------------------------------------\n");
}

// ---------------------- Packet Display ----------------------
void displayPacket(Packet p) {
    printf("Source IP: %s\n", p.sourceIP);
    printf("Port: %d\n", p.port);
    printf("Type: %s\n", p.type);
    printf("Size: %d bytes\n", p.size);
}

// ---------------------- Firewall Logic ----------------------
int isMalicious(Packet p) {
    if (strcmp(p.sourceIP, "192.168.1.100") == 0)
        return 1; // Blacklisted IP
    if (p.port == 23 || p.port == 6666)
        return 1; // Suspicious ports
    if (p.size > 1000)
        return 1; // Possible DoS attempt
    return 0; // Safe
}

// ---------------------- Main Program ----------------------
int main() {
    Queue q;
    Stack blocked;
    initQueue(&q);
    initStack(&blocked);

    int choice;
    Packet temp;

    do {
        printf("\n==============================\n");
        printf("   PACKET FILTER SIMULATOR\n");
        printf("==============================\n");
        printf("1. Add incoming packet\n");
        printf("2. Process (Block) next packet\n");
        printf("3. Show queued packets\n");
        printf("4. Show blocked packets\n");
        printf("5. Exit\n");
        printf("Enter choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                printf("Enter source IP: ");
                scanf("%s", temp.sourceIP);
                printf("Enter port: ");
                scanf("%d", &temp.port);
                printf("Enter type (TCP/UDP): ");
                scanf("%s", temp.type);
                printf("Enter size (bytes): ");
                scanf("%d", &temp.size);
                enqueue(&q, temp);
                break;

            case 2:
                if (!isEmptyQueue(&q)) {
                    Packet p = dequeue(&q);
                    printf("\nProcessing packet...\n");
                    displayPacket(p);

                    if (isMalicious(p)) {
                        printf(RED "⚠️  Packet BLOCKED (malicious)\n" RESET);
                        push(&blocked, p);
                    } else {
                        printf(GREEN "✅ Packet ALLOWED (safe)\n" RESET);
                    }
                } else {
                    printf(YELLOW "No packets to process.\n" RESET);
                }
                break;

            case 3:
                displayQueue(&q);
                break;

            case 4:
                displayBlocked(&blocked);
                break;

            case 5:
                printf(GREEN "Exiting simulator... Goodbye!\n" RESET);
                break;

            default:
                printf(RED "Invalid choice! Try again.\n" RESET);
        }

    } while (choice != 5);

    return 0;
}
