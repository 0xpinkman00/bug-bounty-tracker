import {useCallback, useEffect, useState} from 'react';

export type Page<T> = {items:T[]; total:number; offset:number; limit:number};
export type Program = {id:number; name:string; platform:string; platform_program_id:string; program_url:string; max_bounty:string|null; status:string; first_seen_at:string; last_changed_at:string|null; latest_activity_at?:string|null; assets?:Asset[]; repositories?:Repository[]; releases?:Release[]; events?:Event[]};
export type Asset = {id:number; type:string; value:string; url:string|null; in_scope:boolean};
export type Repository = {id:number; owner:string; name:string; url:string; default_branch:string|null; last_commit_sha:string|null; last_scanned_at:string|null; next_scan_at:string|null; scan_failures:number; scan_interval:number; archived:boolean; programs?:Program[]; commits?:Commit[]; releases?:Release[]; tags?:Tag[]; events?:Event[]};
export type Commit = {id:number; sha:string; message:string; author:string|null; committed_at:string|null; files:{id:number;filename:string;status:string;language:string|null;dependency_change:boolean;additions:number;deletions:number}[]};
export type Release = {id:number; repository_id:number; repository_name?:string; tag:string; name:string|null; published_at:string|null; release_url:string};
export type ReleasePollEntry = {repository_id:number; repository:string; status:'checked'|'failed'; fetched:number|null; new_releases:{id:number;tag:string;name:string|null;published_at:string|null;url:string}[]; error:string|null};
export type ReleasePollRun = {id:string; status:'running'|'completed'|'completed_with_errors'; started_at:string; completed_at:string|null; total_repositories:number; checked_count:number; new_release_count:number; error_count:number; notification_status?:'pending'|'sent'|'unavailable'|'disabled'|'failed'; repositories:ReleasePollEntry[]};
export type Tag = {id:number; name:string; commit_sha:string|null};
export type Event = {id:number; event_type:string; repository_id:number|null; program_id:number|null; repository_name?:string|null; program_name?:string|null; payload:Record<string,unknown>; identity:string; created_at:string; read_at:string|null};
export type Run = {id:number; source:string; status:'queued'|'running'|'pausing'|'paused'|'stopping'|'stopped'|'completed'|'failed'; next_index:number; started_at:string|null; discovered_count:number; processed_count:number; created_count:number; updated_count:number; error_count:number; last_error:string|null; created_at:string; completed_at:string|null};
export type Source = {name:string; program_count:number; latest_run:Run|null; runs?:Run[]};
export type Overview = {stats:{programs:number;repositories:number;releases:number;releases_7d:number;unread_events:number;scan_failures:number};recent_releases:Release[];recent_events:Event[];sources:Source[]};

export async function api<T>(path:string, options?:RequestInit):Promise<T> {
  const response=await fetch('/api'+path,{...options,headers:{'Content-Type':'application/json',...options?.headers}});
  if(!response.ok){const body=await response.json().catch(()=>({}));throw new Error(typeof body.detail==='string'?body.detail:`Request failed (${response.status})`)}
  return response.json();
}
export function useApi<T>(path:string, interval=0){
  const [data,setData]=useState<T|null>(null),[error,setError]=useState(''),[loading,setLoading]=useState(true);
  const reload=useCallback(async()=>{try{const result=await api<T>(path);setData(result);setError('')}catch(err){setError(err instanceof Error?err.message:'Could not load data')}finally{setLoading(false)}},[path]);
  useEffect(()=>{setLoading(true);void reload();if(!interval)return;const timer=setInterval(()=>void reload(),interval);return()=>clearInterval(timer)},[reload,interval]);
  return {data,error,loading,reload};
}
export function formatDate(value:string|null|undefined, short=false){if(!value)return 'Not yet';return new Intl.DateTimeFormat(undefined,short?{month:'short',day:'numeric'}:{month:'short',day:'numeric',year:'numeric',hour:'numeric',minute:'2-digit'}).format(new Date(value))}
export function relativeDate(value:string|null|undefined){if(!value)return 'Not yet';const difference=Date.now()-new Date(value).getTime();if(difference<0)return formatDate(value,true);const minutes=Math.floor(difference/60000);if(minutes<1)return 'Just now';if(minutes<60)return `${minutes}m ago`;const hours=Math.floor(minutes/60);if(hours<24)return `${hours}h ago`;const days=Math.floor(hours/24);return days<30?`${days}d ago`:formatDate(value,true)}
export function eventLabel(type:string){return type.toLowerCase().replaceAll('_',' ').replace(/\b\w/g,letter=>letter.toUpperCase())}
export function eventDescription(event:Event){const value=event.payload.name||event.payload.tag||event.payload.message||event.payload.value||event.repository_name||event.program_name||event.identity;return String(value||event.identity)}
export const sourceLabel:Record<string,string>={immunefi:'Immunefi',hackenproof:'HackenProof'};
