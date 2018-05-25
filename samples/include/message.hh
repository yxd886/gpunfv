#ifndef MESSAGE_HH
#define MESSAGE_HH

class message{
public:
    char* msg;
    size_t len;

   // Explicit constructors.
    message(char* _msg, size_t _len) {
       assert(msg);
       msg = _msg;
       len=_len;
   }

   // Deconstructors
   ~message() {

   }

   // Copy construct/assign
   message(const message& other) = delete;
   message& operator=(const message& other) = delete;

   // Move construct/asign
   message(message&& other) noexcept
       : msg(other.msg),len(other.len) {
       other.msg = nullptr;
       other.len = 0;
   }
   message& operator=(message&& other) noexcept {
       if(this != &other) {
           this->~message();
           new (this) message(std::move(other));
       }
       return *this;
   }

};



#endif
