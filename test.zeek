global IPuser_Table: table[addr] of set[string] = table();
event http_header(c: connection, is_orig: bool, name: string, value: string)
{
     local source_address: addr = c$id$orig_h;
     if(name=="USER-AGENT") 
     {
          if(source_address in IPuser_Table) 
	  {
               if(to_lower(value) !in IPuser_Table[source_address]) 
	       {
                    add IPuser_Table[source_address][to_lower(value)];
               }
          }
           else 
	   {
               IPuser_Table[source_address] = set(to_lower(value));
          }
     }
}
event zeek_done()
{
     for(source_address in IPuser_Table) 
     {
          if(|IPuser_Table[source_address]| >= 3) 
	  {
               print fmt("%s is a proxy", source_address);
          }
     }
}
