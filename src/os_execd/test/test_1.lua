
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
  print("---LUA: ending lua init")
end

ar.register_add(adder)
ar.register_delete(deleter)
ar.register_init(init)

