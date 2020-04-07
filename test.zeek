global key:set[string]={"USER-AGENT"};
global x:set[string]={};
global cc=0;
global a:addr;


event http_header(c: connection, is_orig: bool, name: string, value: string){
a=c$id$orig_h;
if (name in key){
if (to_lower(value) in x){
;
}
else{
add x[to_lower(value)];
++cc;
}
}
}

event zeek_done(){
if (cc>=3){
print fmt("%s is a proxy",a);
}
}
