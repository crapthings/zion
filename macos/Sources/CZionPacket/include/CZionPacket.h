#ifndef CZION_PACKET_H
#define CZION_PACKET_H
#include <stddef.h>
#include <stdint.h>

/* The opaque handle owns a bounded Rust packet engine and its callback thread. */
typedef struct ZionPacketEngine ZionPacketEngine;
/* Callback bytes are borrowed until return and must be copied by the host. */
typedef void (*ZionPacketCallback)(void *context, const uint8_t *bytes, size_t length);
/* Creation copies a bounded JSON envelope and authenticates asynchronously before ready. */
ZionPacketEngine *zion_packet_create(const uint8_t *data, size_t length, ZionPacketCallback packet, ZionPacketCallback event, void *context);
/* Submission is nonblocking and must be serialized against destruction. */
int32_t zion_packet_send(ZionPacketEngine *engine, const uint8_t *data, size_t length);
/* Destruction joins callbacks and must never execute from a callback itself. */
void zion_packet_destroy(ZionPacketEngine *engine);
#endif
