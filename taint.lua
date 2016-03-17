--metatables stuff
function getbinhandler(op1, op2, event)
    return metable(op1)[event] or metatable(op2)[event]
end

function add_event(op1, op2)
    local o1, o2 = tonumber(op1), tonumber(op2)
    if o1 and o2 then --both operands are numeric?
        return o1 + o2 --'+' here is the primitive 'add'
    else --at least one of the operand is not numeric
        local h = getbinhandler(op1, op2, "__add")
        if h then
            --call the handler with both operands
            return (h(op1, op2))
        else -- no handler available: default behavoir
            --error(...)
        end
    end
end

local taint_metatable = {
    __add = function(lhs, rhs) 
            local taint_table = {}
            local lhs_table = {}
            local rhs_table = {}
            if getmetatable(lhs) ~= 'metataint' then
                lhs_table['val'] = lhs
                lhs_table['tainted'] = false
            else 
                lhs_table = lhs
                taint_table = lhs --done to preserve the metatable
            end 
            if getmetatable(rhs) ~= 'metataint' then
                rhs_table['val'] = rhs
                rhs_table['tainted'] = false
            else 
                rhs_table = rhs
                taint_table = rhs
            end
            if  istainted(lhs) or istainted(rhs) then  
                taint_table['val'] = lhs_table['val'] + rhs_table['val']
                taint_table['tainted'] = true
                return taint_table 
            else
                taint_table['val'] = lhs_table['val'] + rhs_table['val']
                taint_table['tainted'] = false
                return taint_table
            end
    end,
    __sub = function(lhs, rhs) 
            local taint_table = {}
            local lhs_table = {}
            local rhs_table = {}

            if getmetatable(lhs) ~= 'metataint' then
                lhs_table['val'] = lhs
                lhs_table['tainted'] = false
            else --it is a tainttable
                lhs_table = lhs
                taint_table = lhs --done to preserve the metatable
            end 

            if getmetatable(rhs) ~= 'metataint' then
                rhs_table['val'] = rhs
                rhs_table['tainted'] = false
            else 
                rhs_table = rhs
                taint_table = rhs
            end
            if  istainted(lhs) or istainted(rhs) then  
                taint_table['val'] = lhs_table['val'] - rhs_table['val']
                taint_table['tainted'] = true
                return taint_table 
            else
                taint_table['val'] = lhs_table['val'] - rhs_table['val']
                taint_table['tainted'] = false
                return taint_table
        end
    end,
    __mul = function(lhs, rhs) 
            local taint_table = {}
            local lhs_table = {}
            local rhs_table = {}

            if getmetatable(lhs) ~= 'metataint' then
                lhs_table['val'] = lhs
                lhs_table['tainted'] = false
            else --it is a table
                lhs_table = lhs
                taint_table = lhs --done to preserve the metatable
            end 
            
            if getmetatable(rhs) ~= 'metataint' then
                rhs_table['val'] = rhs
                rhs_table['tainted'] = false
            else 
                rhs_table = rhs
                taint_table = rhs
            end
           
            if  istainted(lhs) or istainted(rhs) then  
                taint_table['val'] = lhs_table['val'] * rhs_table['val']
                taint_table['tainted'] = true
                return taint_table 
            else
                taint_table['val'] = lhs_table['val'] * rhs_table['val']
                taint_table['tainted'] = false
                return taint_table
        end
    end,
    __div = function(lhs, rhs) 
            local taint_table = {}
            local lhs_table = {}
            local rhs_table = {}
           
            if getmetatable(lhs) ~= 'metataint' then
                lhs_table['val'] = lhs
                lhs_table['tainted'] = false
            else --it is a table
                lhs_table = lhs
                taint_table = lhs --done to preserve the metatable
            end 

            if getmetatable(rhs) ~= 'metataint' then
                rhs_table['val'] = rhs
                rhs_table['tainted'] = false
            else 
                rhs_table = rhs
                taint_table = rhs
            end
           
            if  istainted(lhs) or istainted(rhs) then  
                taint_table['val'] = lhs_table['val'] / rhs_table['val']
                taint_table['tainted'] = true
                return taint_table 
            else
                taint_table['val'] = lhs_table['val'] / rhs_table['val']
                taint_table['tainted'] = false
                return taint_table
        end
    end,


    __mod = function(lhs, rhs) 
            local taint_table = {}
            local lhs_table = {}
            local rhs_table = {}
            
            if getmetatable(lhs) ~= 'metataint' then
                lhs_table['val'] = lhs
                lhs_table['tainted'] = false
            else --it is a table
                lhs_table = lhs
                taint_table = lhs --done to preserve the metatable
            end 
           
            if getmetatable(rhs) ~= 'metataint' then
                rhs_table['val'] = rhs
                rhs_table['tainted'] = false
            else 
                rhs_table = rhs
                taint_table = rhs
            end
           
            if  istainted(lhs) or istainted(rhs) then  
                taint_table['val'] = lhs_table['val'] - math.floor(lhs_table['val']/rhs_table['val'])*rhs_table['val']
                taint_table['tainted'] = true
                return taint_table 
            else
                taint_table['val'] =  lhs_table['val'] - math.floor(lhs_table['val']/rhs_table['val'])*rhs_table['val']    --because the % gives me an error 
                taint_table['tainted'] = false
                return taint_table
        end
    end,

    __pow = function(lhs, rhs) 
            local taint_table = {}
            local lhs_table = {}
            local rhs_table = {}

            if getmetatable(lhs) ~= 'metataint' then
                lhs_table['val'] = lhs
                lhs_table['tainted'] = false
            else --it is a table
                lhs_table = lhs
                taint_table = lhs --done to preserve the metatable
            end 

            if getmetatable(rhs) ~= 'metataint' then
                rhs_table['val'] = rhs
                rhs_table['tainted'] = false
            else 
                rhs_table = rhs
                taint_table = rhs
            end
           
            if  istainted(lhs) or istainted(rhs) then  
                taint_table['val'] = lhs_table['val'] ^ rhs_table['val']
                taint_table['tainted'] = true
                return taint_table 
            else
                taint_table['val'] = lhs_table['val'] ^ rhs_table['val']
                taint_table['tainted'] = false
                return taint_table
        end
    end,

    __concat = function(lhs, rhs) 
            local taint_table = {}
            local lhs_table = {}
            local rhs_table = {}
           
            if getmetatable(lhs) ~= 'metataint' then
                lhs_table['val'] = lhs
                lhs_table['tainted'] = false
            else --it is a table
                lhs_table = lhs
                taint_table = lhs --done to preserve the metatable
            end 

            if getmetatable(rhs) ~= 'metataint' then
                rhs_table['val'] = rhs
                rhs_table['tainted'] = false
            else 
                rhs_table = rhs
                taint_table = rhs
            end
            if  istainted(lhs) or istainted(rhs) then  
                taint_table['val'] = lhs_table['val'] .. rhs_table['val']
                taint_table['tainted'] = true
                return taint_table 
            else
                taint_table['val'] = lhs_table['val'] .. rhs_table['val']
                taint_table['tainted'] = false
                return taint_table
        end
    end,
    __unm = function(taint_table)
        taint_table['val'] = -taint_table['val']
        return taint_table
    end,
    __eq = function(lhs, rhs) 
            local taint_table = {}
            local lhs_table = {}
            local rhs_table = {}
           
            if getmetatable(lhs) ~= 'metataint' then
                lhs_table['val'] = lhs
                lhs_table['tainted'] = false
            else --it is a table
                lhs_table = lhs
                taint_table = lhs --done to preserve the metatable
            end 

           if getmetatable(rhs) ~= 'metataint' then
                rhs_table['val'] = rhs
                rhs_table['tainted'] = false
            else 
                rhs_table = rhs
                taint_table = rhs
            end
            
            if  istainted(lhs) or istainted(rhs) then  
                taint_table['val'] = lhs_table['val'] == rhs_table['val']
                taint_table['tainted'] = true
                print("taint_table['val'] = ", taint_table['val']) 
                return taint_table['val'] -- should just return taint_table fix later TODO 
            else
                taint_table['val'] = lhs_table['val'] == rhs_table['val']
                taint_table['tainted'] = false
                return taint_table['val'] -- should just return taint_table fix later TODO
            end
    end,

    __lt = function(lhs, rhs) 
            local taint_table = {}
            local lhs_table = {}
            local rhs_table = {}
            
            if getmetatable(lhs) ~= 'metataint' then
                lhs_table['val'] = lhs
                lhs_table['tainted'] = false
            else --it is a table
                lhs_table = lhs
                taint_table = lhs --done to preserve the metatable
            end

            if getmetatable(rhs) ~= 'metataint' then
                rhs_table['val'] = rhs
                rhs_table['tainted'] = false
            else 
                rhs_table = rhs
                taint_table = rhs
            end
            
            if  istainted(lhs) or istainted(rhs) then  
                taint_table['val'] = lhs_table['val'] < rhs_table['val']
                taint_table['tainted'] = true
                print("taint_table['val'] = ", taint_table['val']) 
                return taint_table['val'] -- should just return taint_table fix later TODO 
            else
                taint_table['val'] = lhs_table['val'] < rhs_table['val']
                taint_table['tainted'] = false
                print("taint_table['val'] = ", taint_table['val']) 
                return taint_table['val'] -- should just return taint_table fix later TODO
            end
    end,
   
    __le = function(lhs, rhs) 
            local taint_table = {}
            local lhs_table = {}
            local rhs_table = {}
           
            if getmetatable(lhs) ~= 'metataint' then
                lhs_table['val'] = lhs
                lhs_table['tainted'] = false
            else --it is a table
                lhs_table = lhs
                taint_table = lhs --done to preserve the metatable
            end 
           
            if getmetatable(rhs) ~= 'metataint' then
                rhs_table['val'] = rhs
                rhs_table['tainted'] = false
            else 
                rhs_table = rhs
                taint_table = rhs
            end
           
            if  istainted(lhs) or istainted(rhs) then  
                taint_table['val'] = lhs_table['val'] <= rhs_table['val']
                taint_table['tainted'] = true
                return taint_table['val'] -- should just return taint_table fix later TODO 
            else
                taint_table['val'] = lhs_table['val'] <= rhs_table['val']
                taint_table['tainted'] = false
                return taint_table['val'] -- should just return taint_table fix later TODO
            end
    end,
    __call = function()
        print("I don't know how this metatable function works") --TODO
    end,
    __tostring = function(t)
        return tostring(t['val'])
    end,
   
    __index = function (tbl, key)
        return tbl['val']
    end, 
   
    __metatable = "metataint"
}


-- taint analysis stuff
function taint(value)
    if type(value) == 'table' and getmetatable(value) == 'metataint' then
        value['tainted'] = true 
        return value
    end
    local taint_table = {}
    setmetatable(taint_table, taint_metatable)
    taint_table['val'] = value --val and tainted should be some constants 
    taint_table['tainted'] = true 
    return taint_table
end

function istainted(value)
    --returns taint_table[tainted]
    --if value is not a taint_table (has keys of 'val' and 'tainted')we should construct a taint table with 'taint' of value false
    --TODO check to see 
    if type(value) == 'table' and getmetatable(value) == 'metataint'then
        return value['tainted']
    else 
        local taint_table = {} 
        taint_table['val'] = value
        taint_table['tainted'] = false
        return taint_table['tainted'] --, taint_table --maybe return both whether it is tainted and the taint table?
   end 
end
something = taint(123)
somethingtrue = taint(true)
somethingfalse = taint(false)
somestring = taint("somestring")

print("-----BOOLEAN TESTING-----")
print("true and true = ", somethingtrue and somethingtrue)
print("true or true = ", somethingtrue or somethingtrue)
print("true and false = ", somethingtrue and somethingfalse)
print("true or false = ", somethingtrue or somethingfalse)
print("false or false = ", somethingfalse or somethingfalse)
print("false and false = ", somethingfalse and somethingfalse)

print("\n-----NUMBER TESTING-----")
print("something = ", something)
--print("getmetatable(something)", getmetatable(something))
print("something - 1 = ", something - 1)
print("something", something)
print("istainted(something)", istainted(something))
something = 200 - something
print("something = 200 - something",  something)
something = something + 123
print("something = something + 123",  something)
print("123 + something = ", 123 + something)
print(something)
print("something - 123 = ", something - 123)
print("something = ", something)
something = 492 - something
print("492 - something = ", something)
print("something * 2 = ", something * 2)
print(istainted(something))
print("something / 2 = ", something / 2)
print("something ^ 2 = ", something ^ 2)
print("something .. 2(concat) = ", something .. 2)

print("\n-----UNARY TESTING-----")
print("-something = ", -something)


print("\n-----COMPARISON TESTING-----")
print("something == something", something == something) --meta tables do a realy annoying thing were it will apply the metatable stuff to the variable even if i am printing
print(" something < something", something < something)
--print(" something <= something", something <= something)
--print(" something > something", something > something)
--print(" something >= something", something >= something)
--print("getmetatable(something)", getmetatable(something))
--print(1 < something) --why? TODO fix
--print(something < 1)

print("\n-----STRING TESTING-----")
print("somestring = ", somestring)
print("somestring..somestring", somestring..somestring)
print("somestring = ", somestring)
print("somestring == somestring", somestring == 'somestring')
print("somestring == 'somestringsomestring'", somestring == 'somestringsomestring')
print("somestring < somestring", somestring < somestring)
print("somestring is probably a boolean now... somestring = ", somestring)
--TODO test with table as values i am worried about calling taintedtable[0] will just call the metatable which retrieves taintedtable['val']
