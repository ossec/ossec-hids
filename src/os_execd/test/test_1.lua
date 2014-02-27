
print("---LUA: lua starting")

function adder(...) 
  print("---LUA: adder -> LUA")
  print(...)
end

function deleter(...)
  print("---LUA: delete -> LUA")
  print(...)
end

function init()
  print("---LUA: starting lua init")
  ar.register_add(adder)
  ar.register_delete(deleter)
  print("---LUA: ending lua init")
end
init()
print("---LUA: lua ending ")
