#ifndef MESSAGE_HH
#define MESSAGE_HH

class message{
public:
    char* msg;
    size_t length;

   // Explicit constructors.
    message(char* _msg, size_t _len) {
       assert(msg);
       msg = _msg;
       length=_len;
   }

   // Deconstructors
   ~message() {

   }

   // Copy construct/assign
   message(const message& other) = delete;
   message& operator=(const message& other) = delete;

   // Move construct/asign
   message(message&& other) noexcept
       : msg(other.msg),length(other.length) {
       other.msg = nullptr;
       other.length = 0;
   }
   message& operator=(message&& other) noexcept {
       if(this != &other) {
           this->~message();
           new (this) message(std::move(other));
       }
       return *this;
   }

   size_t len(){
       return length;
   }

};



#endif
