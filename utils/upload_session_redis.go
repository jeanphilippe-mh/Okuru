package utils

import "github.com/gomodule/redigo/redis"

// UploadReadyLua defines the shared precondition and mutation used by the
// archive publication transaction and crash recovery. Call check before any
// writes, then apply only after every Redis and storage precondition holds.
const UploadReadyLua = `local function checkUploadReady(sessionKey,publicationID)
 if not publicationID or publicationID=='' then return 'not_ready' end
 local state,prev=unpack(redis.call('HMGET',sessionKey,'state','publication_id'))
 if prev~=publicationID then return 'not_ready' end
 if state=='ready' then return 'already_ready' end
 if state~='finalizing' then return 'not_ready' end
 return nil
end
local function applyUploadReady(sessionKey,indexKey,id,sealedResult,publishedMs,shareExpiryMs)
 local deadline=math.min(shareExpiryMs,publishedMs+86400000)
 redis.call('HSET',sessionKey,'state','ready','result',sealedResult,'share_expiry',shareExpiryMs,'until',deadline)
 redis.call('ZADD',indexKey,deadline,id)
 redis.call('PEXPIREAT',sessionKey,deadline)
end
`

var uploadSessionScript = redis.NewScript(3, UploadReadyLua+`local key,idx,admission=KEYS[1],KEYS[2],KEYS[3]
local id,gen,op,proof=ARGV[1],ARGV[2],ARGV[3],ARGV[4]
local clock=redis.call('TIME')
local now=tonumber(clock[1])*1000+math.floor(tonumber(clock[2])/1000)
local idle=1800000
local keep=86400000
local function same(a,b)
 if not a or not b or #a~=#b then return false end
 local diff=0
 for i=1,#a do diff=bit.bor(diff,bit.bxor(string.byte(a,i),string.byte(b,i))) end
 return diff==0
end
local function schedule(k,i,untilAt,terminal)
 redis.call('HSET',k,'until',untilAt)
 redis.call('ZADD',idx,untilAt,i)
 redis.call('PEXPIREAT',k,untilAt+(terminal and 0 or keep))
end
local function finish(k,i,state,when)
 redis.call('HSET',k,'state',state)
 redis.call('HDEL',k,'envelope','result','publication_id')
 schedule(k,i,when+keep,true)
end
local function normalize(k,i,force)
 local state,deadline,generation=unpack(redis.call('HMGET',k,'state','until','generation'))
 if not state then redis.call('ZREM',idx,i);return nil end
 if state=='open' or state=='receiving' or (state=='finalizing' and force) then
  if generation~=gen then finish(k,i,'interrupted',now);return 'interrupted' end
  if state~='finalizing' and tonumber(deadline)<=now then finish(k,i,'expired',tonumber(deadline));return 'expired' end
 end
 return state
end
local function active(st) return st=='open' or st=='receiving' or st=='finalizing' end
local function touch()
 local absolute=tonumber(redis.call('HGET',key,'absolute'))
 schedule(key,id,math.min(absolute,now+idle),false)
end
if op=='sweep' then
 local ids=redis.call('ZRANGE',idx,0,255)
 for _,entry in ipairs(ids) do normalize(ARGV[5]..entry,entry,true) end
 return {'ok'}
end
local state=normalize(key,id,false)
if op=='owns_parts' then
 if active(state) and redis.call('HGET',key,'mode')=='blocks' and redis.call('HGET',key,'generation')==gen then return {'ok','1'} end
 return {'ok','0'}
end
if op=='create' then
 if state then
  if not same(redis.call('HGET',key,'creator'),proof) then return {'not_found'} end
  if not active(state) and state~='ready' then return {state} end
  if not same(redis.call('HGET',key,'fingerprint'),ARGV[6]) then return {'manifest_conflict'} end
  return {'replay'}
 end
 if ARGV[12]~='1' or redis.call('HGET',admission,'api')~='open' then return {'closed'} end
 if ARGV[5]=='blocks' and (ARGV[13]~='1' or redis.call('HGET',admission,'blocks')~='open') then return {'closed'} end
 local entries=redis.call('ZRANGE',idx,0,255)
 local count=0
 for _,entry in ipairs(entries) do
  local other=ARGV[14]..entry
  local otherState=normalize(other,entry,false)
  if active(otherState) then
   count=count+1
   if ARGV[10]~='' and redis.call('HGET',other,'identity')==ARGV[10] then return {'capacity'} end
  end
 end
 if count>=4 or redis.call('ZCARD',idx)>=256 then return {'capacity'} end
 local clientRate=ARGV[14]..'rate_'..ARGV[16]
 local globalRate=ARGV[14]..'rate_global'
 local clientLimit=ARGV[10]=='' and 100 or 20
 if tonumber(redis.call('GET',clientRate) or '0')>=clientLimit or tonumber(redis.call('GET',globalRate) or '0')>=100 then return {'rate_limit'} end
 local newKeys=4-redis.call('EXISTS',idx,clientRate,globalRate)
 if redis.call('DBSIZE')+newKeys+128>tonumber(ARGV[11]) then return {'redis_capacity'} end
 redis.call('HSET',key,'state','open','generation',gen,'creator',proof,'status',ARGV[7],'mode',ARGV[5],'fingerprint',ARGV[6],'envelope',ARGV[8],'files',ARGV[15],'total',ARGV[9],'body_total',-1,'bytes',0,'parts',0,'absolute',now+14400000,'identity',ARGV[10])
 for i=1,tonumber(ARGV[15]) do redis.call('HSET',key,'size:'..(i-1),ARGV[16+i]) end
 if redis.call('INCR',clientRate)==1 then redis.call('PEXPIRE',clientRate,keep) end
 if redis.call('INCR',globalRate)==1 then redis.call('PEXPIRE',globalRate,keep) end
 touch()
 return {'created'}
end
if not state then return {'not_found'} end
if op=='commit_sealed' or op=='interrupt_publication' then
 local reason=checkUploadReady(key,ARGV[5])
 if reason then return {reason} end
 if op=='interrupt_publication' then finish(key,id,'interrupted',now);return {'ok'} end
 local expiry=tonumber(ARGV[7])
 if not expiry or expiry<=now then return {'expired'} end
 applyUploadReady(key,idx,id,ARGV[6],now,expiry)
 return {'ok'}
end
local creator=same(redis.call('HGET',key,'creator'),proof)
local watcher=same(redis.call('HGET',key,'status'),proof)
if not creator and not (op=='read' and ARGV[5]=='1' and watcher) then return {'not_found'} end
if op=='abort' and state=='aborted' then return {'ok'} end
if not active(state) and state~='ready' and creator then return {state} end
if op=='read' then
 local v=redis.call('HMGET',key,'mode','bytes','total','until','body_total')
 return {'ok',state,v[1],v[2],v[3],v[4],v[5],creator and (redis.call('HGET',key,'envelope') or '') or '',creator and '1' or '0'}
end
if op=='result' then
 if state~='ready' then return {'not_ready'} end
 return {'ok',redis.call('HGET',key,'result'),redis.call('HGET',key,'share_expiry')}
end
if state=='ready' then return {'already_ready'} end
if op=='reject_reservation' then
 if state~='open' or redis.call('HGET',key,'mode')~='blocks' then return {'busy'} end
 finish(key,id,'aborted',now);return {'ok'}
end
if op=='abort' then
 if state=='finalizing' then return {'busy'} end
 finish(key,id,'aborted',now);return {'ok'}
end
if redis.call('HGET',key,'generation')~=gen then return {'interrupted'} end
if op=='touch' then
 if state~='open' and state~='receiving' then return {'busy'} end
 touch(); return {'ok'}
end
local mode=redis.call('HGET',key,'mode')
if op=='begin_multipart' then
 if mode~='multipart' then return {'wrong_mode'} end
 if state~='open' then return {'busy'} end
 redis.call('HSET',key,'state','receiving','body_total',ARGV[5],'bytes',0);touch();return {'ok'}
end
if op=='reset' then
 if mode~='multipart' then return {'wrong_mode'} end
 if state~='receiving' then return {'busy'} end
 redis.call('HSET',key,'state','open','body_total',-1,'bytes',0);return {'ok'}
end
if op=='progress' then
 if mode~='multipart' or state~='receiving' then return {'busy'} end
 local n=tonumber(ARGV[5]);local old=tonumber(redis.call('HGET',key,'bytes'))
 if n>old then redis.call('HSET',key,'bytes',n);touch() end
 return {'ok'}
end
if op=='offset' or op=='append' then
 if mode~='blocks' then return {'wrong_mode'} end
 local f='offset:'..ARGV[5];local size=tonumber(redis.call('HGET',key,'size:'..ARGV[5]))
 if not size then return {'not_found'} end
 local offset=tonumber(redis.call('HGET',key,f) or '0')
 if op=='offset' then return {'ok',tostring(offset)} end
 if state~='receiving' and state~='open' then return {'busy'} end
 local old,new=tonumber(ARGV[6]),tonumber(ARGV[7])
 if old~=offset or new<old or new>size then return {'offset_conflict'} end
 if new==old then return {'ok'} end
 if tonumber(redis.call('HGET',key,'parts'))>=2048 then return {'part_limit'} end
 local part=redis.call('HINCRBY',key,'parts',1);redis.call('HINCRBY',key,'bytes',new-old)
 redis.call('HSET',key,'state','receiving',f,new,'part:'..part,ARGV[5]..':'..ARGV[6]..':'..ARGV[7]);touch();return {'ok'}
end
if op=='begin_publication' then
 if state=='finalizing' then return {'busy'} end
 if mode=='blocks' and redis.call('HGET',key,'bytes')~=redis.call('HGET',key,'total') then return {'not_ready'} end
 if mode=='multipart' and state~='receiving' then return {'not_ready'} end
 redis.call('HSET',key,'state','finalizing');touch();return {'ok'}
end
if op=='bind' then
 if state~='finalizing' then return {'not_ready'} end
 local previous=redis.call('HGET',key,'publication_id')
 if previous and previous~=ARGV[5] then return {'busy'} end
 redis.call('HSET',key,'publication_id',ARGV[5]);return {'ok'}
end
if op=='revert_finalizing' then
 if state~='finalizing' or redis.call('HEXISTS',key,'publication_id')==1 then return {'busy'} end
 if mode=='blocks' then redis.call('HSET',key,'state','receiving') else redis.call('HSET',key,'state','open','bytes',0,'body_total',-1) end
 return {'ok'}
end
return {'invalid_request'}`)
