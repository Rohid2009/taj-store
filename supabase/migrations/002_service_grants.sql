grant execute on function public.register_profile(uuid,text,text) to service_role;
grant execute on function public.my_uid(), public.my_sid(), public.is_admin(), public.priv(), public.directory() to service_role;
