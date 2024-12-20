
declare
    rst              varchar2(4000);
begin
    
    for t in (
        select * from tmp_table
    ) loop
        rst := t.prev;
        
        for m in (
            select * from master_data
            order by rank asc -- 우선순위
        ) loop        
            -- 그냥 다 변경하면서 구분자 _ 붙임
            rst := replace(rst, m.kor, '_'||m.eng||'_');
        end loop;
        
        -- 구분자 두번 붙은거 한개로 바꿈
        rst := replace(rst, '__', '_');
        
        -- 첫번째 문자열에 구분자가 있으면 제거함
        if substr(rst, 1, 1) = '_' then 
            rst := substr(rst, 2, length(rst));
        end if;
        
        -- 마지막 문자열에 구분자가 있으면 제거함
        if substr(rst, -1) = '_' then 
            rst := substr(rst, 1, length(rst)-1);
        end if;
        
        dbms_output.put_line(t.prev || ' -> '||rst);

        update tmp_table 
           set next = rst
         where no = t.no;
      
    end loop;
    
    dbms_output.put_line(sqlerrm(sqlcode));

exception   
    when others then
        dbms_output.put_line(sqlerrm(sqlcode));
end;