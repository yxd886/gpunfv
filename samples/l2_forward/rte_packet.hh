/*
 * rte_packet.hh
 *
 *  Created on: Apr 4, 2018
 *      Author: xiaodongyi
 */

#ifndef SAMPLES_L2_FORWARD_RTE_PACKET_HH_
#define SAMPLES_L2_FORWARD_RTE_PACKET_HH_


class rte_packet {


   rte_mbuf* _mbuf;

public:
   // Explicit constructors.
   rte_packet(rte_mbuf* mbuf) {
       assert(mbuf);
       assert(rte_pktmbuf_is_contiguous(mbuf));
       _mbuf = mbuf;
   }

   rte_packet()
       : _mbuf(nullptr) {}

   // Deconstructors
   ~rte_packet() {

   }

   // Copy construct/assign
   rte_packet(const rte_packet& other) = delete;
   rte_packet& operator=(const rte_packet& other) = delete;

   // Move construct/asign
   rte_packet(rte_packet&& other) noexcept
       : _mbuf(other._mbuf) {
       other._mbuf = nullptr;
   }
   rte_packet& operator=(rte_packet&& other) noexcept {
       if(this != &other) {
           this->~rte_packet();
           new (this) rte_packet(std::move(other));
       }
       return *this;
   }

   // Boolean operator overloads
   explicit operator bool() {
       return bool(_mbuf);
   }

   // Get a header pointer.
   template <typename Header>
   Header* get_header(size_t offset = 0) {
       assert(_mbuf);
       if(offset+sizeof(Header) > rte_pktmbuf_pkt_len(_mbuf)) {
           return nullptr;
       }
       return reinterpret_cast<Header*>(rte_pktmbuf_mtod_offset(_mbuf, void*, offset));
   }

   char* get_header(size_t offset, size_t size) {
       if(offset+size > rte_pktmbuf_pkt_len(_mbuf)) {
           return nullptr;
       }

       return reinterpret_cast<char*>(rte_pktmbuf_mtod_offset(_mbuf, void*, offset));
   }

   // Trim some payload from front of the packet
   void trim_front(size_t how_much) {
       assert(_mbuf);
       assert(how_much <= rte_pktmbuf_pkt_len(_mbuf));
       rte_pktmbuf_adj(_mbuf, how_much);
   }

   // Trim some payload from the back of the packet
   void trim_back(size_t how_much) {
       assert(_mbuf);
       assert(how_much <= rte_pktmbuf_pkt_len(_mbuf));
       rte_pktmbuf_trim(_mbuf, how_much);
   }

   // Append some content to the back of the packet
   void append(size_t how_much) {
       assert(_mbuf);
       assert(how_much <= rte_pktmbuf_tailroom(_mbuf));
       rte_pktmbuf_append(_mbuf, how_much);
   }

   // Prepend a header to the front of the packet.
   template <typename Header>
   Header* prepend_header(size_t extra_size = 0) {
       assert(_mbuf);
       assert(sizeof(Header)+extra_size <= rte_pktmbuf_headroom(_mbuf));
       auto h = rte_pktmbuf_prepend(_mbuf, sizeof(Header) + extra_size);
       return new (h) Header{};
   }

   // Obtain the length of the packet.
   unsigned len() const {
       assert(_mbuf);
       return rte_pktmbuf_pkt_len(_mbuf);
   }

   // Get copy of the packet represented in net::packet
   rte_mbuf*
   get_packet() {
       // Fast path, consider removing it for stable code.
       return _mbuf;
   }

private:


   // Explicitly invalidate _mbuf and return the original
   // _mbuf.
   // Be extra careful!! This is used internally by different
   // devices to directly send an rte_packet. And I don't know
   // hide it from public access. User should not
   // call this function by any means.
   rte_mbuf* release_mbuf() {
       rte_mbuf* tmp = _mbuf;
       _mbuf = nullptr;
       return tmp;
   }

   // How are you going to call this constructor, if you
   // can't build a mbuf from the rte_mpool?



};


#endif /* SAMPLES_L2_FORWARD_RTE_PACKET_HH_ */
