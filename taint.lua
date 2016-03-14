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
local numbers_metatable = {
    __add = function(lhs, rhs) --add event handler
            --make sure to get the same value because i don't know how to cast
            local taint_table = {}
            local lhs_table = {}
            local rhs_table = {}
            --setmetatable(taint_table, numbers_metatable) --is this legal?
            if type(lhs) == 'number' then
                lhs_table['val'] = lhs
                lhs_table['tainted'] = false
            else --it is a table
                lhs_table = lhs
            end 
            if type(rhs) == 'number' then
                rhs_table['val'] = rhs
                rhs_table['tainted'] = false
            else --it is a table
                rhs_table = rhs
             end
                --if they are one is tainted
            if  istainted(lhs) or istainted(rhs) then 
                taint_table['val'] = lhs_table['val'] + rhs_table['val']
                taint_table['tainted'] = true
                setmetatable(taint_table, numbers_metatable)
                return taint_table --was return rhs_table['val'] + lhs_table['val']
            else
                taint_table['val'] = lhs_table['val'] + rhs_table['val']
                taint_table['tainted'] = false
                setmetatable(taint_table, numbers_metatable)
                return taint_table
            end
    end,
    __sub = function(lhs, rhs) --add event handler
            --make checks for tainted values and such
            --if they are both tainted or not tainted
            if  istainted(lhs) == istainted(rhs) then 
                return lhs['val'] - rhs['val']
            end
    end,
    __eq = function (lhs, rhs)
        if istainted(lhs) == istainted(rhs) then
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
        --TODO make sure assign works
    end,
    __tostring = function(t)
        --local sum = 0
        --for _, v in pairs(t) do sum = sum + v end
        setmetatable(t, numbers_metatable)
        return tostring(t['val'])
    end
}


-- taint analysis stuff
function taint(value)
    if type(value) == 'table' and value['tainted'] ~= nill then --probably need a hook instead
        setmetatable(value, numbers_metatable) --TODO check to see if it is numbers, string, boolean etc
        value['tainted'] = true --need the address of of value to be changed?
        return value
    end
    local taint_table = {}
    setmetatable(taint_table, numbers_metatable)
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
something_else = {}
something_else['val'] = 321
something_else = taint(something_else) --doing taint(something_else) by itself will not taint something_else

print("something = ", something) 
--something['tainted'] = false

setmetatable(something, numbers_metatable)
print("something + 123 = ", something + 123)
print("something", something)


setmetatable(something, numbers_metatable)
something = 123 + something
print("something = 123 + something",  something)
--something = something + 123
print("something = something + 123",  something)

setmetatable(something, numbers_metatable)
print("123 + something = ", 123 + something)
print(something)
