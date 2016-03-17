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

local x = {value = 5}
local taint_metatable = {
    __add = function(lhs, rhs) 
            local taint_table = {}
            local lhs_table = {}
            local rhs_table = {}
            if type(lhs) == 'number' then
                lhs_table['val'] = lhs
                lhs_table['tainted'] = false
            else --it is a table
                lhs_table = lhs
                if lhs['tainted'] then --and getmetatable() = numbers_metatable
                    taint_table = lhs --done to preserve the metatable
                end
            end 
            if type(rhs) == 'number' then
                rhs_table['val'] = rhs
                rhs_table['tainted'] = false
            else 
                rhs_table = rhs
                if rhs['tainted'] ~= nil then
                    taint_table = rhs
                end
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
            if type(lhs) == 'number' then
                lhs_table['val'] = lhs
                lhs_table['tainted'] = false
            else --it is a table
                lhs_table = lhs
                if lhs['tainted'] then
                    taint_table = lhs --done to preserve the metatable
                end
            end 
            if type(rhs) == 'number' then
                rhs_table['val'] = rhs
                rhs_table['tainted'] = false
            else 
                rhs_table = rhs
                if rhs['tainted'] ~= nil then
                    taint_table = rhs
                end
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
            if type(lhs) == 'number' then
                lhs_table['val'] = lhs
                lhs_table['tainted'] = false
            else --it is a table
                lhs_table = lhs
                if lhs['tainted'] then
                    taint_table = lhs --done to preserve the metatable
                end
            end 
            if type(rhs) == 'number' then
                rhs_table['val'] = rhs
                rhs_table['tainted'] = false
            else 
                rhs_table = rhs
                if rhs['tainted'] ~= nil then
                    taint_table = rhs
                end
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
            if type(lhs) == 'number' then
                lhs_table['val'] = lhs
                lhs_table['tainted'] = false
            else --it is a table
                lhs_table = lhs
                if lhs['tainted'] then
                    taint_table = lhs --done to preserve the metatable
                end
            end 
            if type(rhs) == 'number' then
                rhs_table['val'] = rhs
                rhs_table['tainted'] = false
            else 
                rhs_table = rhs
                if rhs['tainted'] ~= nil then
                    taint_table = rhs
                end
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
            if type(lhs) == 'number' then
                lhs_table['val'] = lhs
                lhs_table['tainted'] = false
            else --it is a table
                lhs_table = lhs
                if lhs['tainted'] then
                    taint_table = lhs --done to preserve the metatable
                end
            end 
            if type(rhs) == 'number' then
                rhs_table['val'] = rhs
                rhs_table['tainted'] = false
            else 
                rhs_table = rhs
                if rhs['tainted'] ~= nil then
                    taint_table = rhs
                end
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
            if type(lhs) == 'number' then
                lhs_table['val'] = lhs
                lhs_table['tainted'] = false
            else --it is a table
                lhs_table = lhs
                if lhs['tainted'] then
                    taint_table = lhs --done to preserve the metatable
                end
            end 
            if type(rhs) == 'number' then
                rhs_table['val'] = rhs
                rhs_table['tainted'] = false
            else 
                rhs_table = rhs
                if rhs['tainted'] ~= nil then
                    taint_table = rhs
                end
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
            if type(lhs) == 'number' then
                lhs_table['val'] = lhs
                lhs_table['tainted'] = false
            else --it is a table
                lhs_table = lhs
                if lhs['tainted'] then
                    taint_table = lhs --done to preserve the metatable
                end
            end 
            if type(rhs) == 'number' then
                rhs_table['val'] = rhs
                rhs_table['tainted'] = false
            else 
                rhs_table = rhs
                if rhs['tainted'] ~= nil then
                    taint_table = rhs
                end
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



    __eq = function(lhs, rhs) 
            local taint_table = {}
            local lhs_table = {}
            local rhs_table = {}
            if type(lhs) == 'number' then
                lhs_table['val'] = lhs
                lhs_table['tainted'] = false
            else --it is a table
                lhs_table = lhs
                if lhs['tainted'] then --and getmetatable() = numbers_metatable
                    taint_table = lhs --done to preserve the metatable
                end
            end 
            if type(rhs) == 'number' then
                rhs_table['val'] = rhs
                rhs_table['tainted'] = false
            else 
                rhs_table = rhs
                if rhs['tainted'] ~= nil then
                    taint_table = rhs
                end
             end
            if  istainted(lhs) or istainted(rhs) then  
                taint_table['val'] = lhs_table['val'] == rhs_table['val']
                taint_table['tainted'] = true
                return taint_table 
            else
                taint_table['val'] = lhs_table['val'] == rhs_table['val']
                taint_table['tainted'] = false
                return taint_table
            end
    end,
    __lt = function(lhs, rhs) 
            local taint_table = {}
            local lhs_table = {}
            local rhs_table = {}
            if type(lhs) == 'number' then
                lhs_table['val'] = lhs
                lhs_table['tainted'] = false
            else --it is a table
                lhs_table = lhs
                if lhs['tainted'] then --and getmetatable() = numbers_metatable
                    taint_table = lhs --done to preserve the metatable
                end
            end 
            if type(rhs) == 'number' then
                rhs_table['val'] = rhs
                rhs_table['tainted'] = false
            else 
                rhs_table = rhs
                if rhs['tainted'] ~= nil then
                    taint_table = rhs
                end
             end
            if  istainted(lhs) or istainted(rhs) then  
                taint_table['val'] = lhs_table['val'] < rhs_table['val']
                taint_table['tainted'] = true
                return taint_table 
            else
                taint_table['val'] = lhs_table['val'] < rhs_table['val']
                taint_table['tainted'] = false
                return taint_table
            end
    end,
    __le = function(lhs, rhs) 
            local taint_table = {}
            local lhs_table = {}
            local rhs_table = {}
            if type(lhs) == 'number' then
                lhs_table['val'] = lhs
                lhs_table['tainted'] = false
            else --it is a table
                lhs_table = lhs
                if lhs['tainted'] then --and getmetatable() = numbers_metatable
                    taint_table = lhs --done to preserve the metatable
                end
            end 
            if type(rhs) == 'number' then
                rhs_table['val'] = rhs
                rhs_table['tainted'] = false
            else 
                rhs_table = rhs
                if rhs['tainted'] ~= nil then
                    taint_table = rhs
                end
             end
            if  istainted(lhs) or istainted(rhs) then  
                taint_table['val'] = lhs_table['val'] <= rhs_table['val']
                taint_table['tainted'] = true
                return taint_table 
            else
                taint_table['val'] = lhs_table['val'] <= rhs_table['val']
                taint_table['tainted'] = false
                return taint_table
            end
    end,

--[[
    __eq = function (lhs, rhs)
        if istainted(lhs) or  istainted(rhs) then --TODO make a boolean taint metatable to return
            return lhs.value == rhs.value
        end
    end,
    __lt = function (lhs, rhs)
        if istainted(lhs) == istainted(rhs) then
            return lhs.value < rhs.value
        end
    end,
    __le = function (lhs, rhs) -- not really necessary, just improves "<=" and ">" performance
        if istainted(lhs) == istainted(rhs) then
            return lhs.value <= rhs.value
        end
    end,
    ]]--
    __tostring = function(t)
        --local sum = 0
        --for _, v in pairs(t) do sum = sum + v end
        --setmetatable(t, numbers_metatable)
        return tostring(t['val'])
    end,
    __index = function (tbl, key)
        return tbl['val']
    end
}


-- taint analysis stuff
function taint(value)
    if type(value) == 'table' and value['tainted'] ~= nill then --probably should check against the metatable instead
        setmetatable(value, taint_metatable) --TODO check to see if it is numbers, string, boolean etc
        value['tainted'] = true --need the address of of value to be changed?
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
    if type(value) == 'table' and value['tainted'] ~= nill then
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
--print("true + true = ", true + true)
--print("true + false = ", true + false)
print("true and true = ", somethingtrue and somethingtrue)
print("true or true = ", somethingtrue or somethingtrue)
print("true and false = ", somethingtrue and somethingfalse)
print("true or false = ", somethingtrue or somethingfalse)
print("false or false", somethingfalse or somethingfalse)
print("false and false", somethingfalse and somethingfalse)


----[[
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

print(something == something)
print(something < something)
print(something < 1)
----]]
