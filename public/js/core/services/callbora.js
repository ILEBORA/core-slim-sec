__BORA_REGISTER_SERVICE__('callbora', async function(scope){

    const hooks   = await scope.getService('hooks');
    const logger  = await scope.getService('logger');
    const config  = await scope.config || {};
    // const $       = await scope.getService('jquery');

    // if(!$){
    //     throw new Error('callbora requires jquery service');
    // }

    function resolveErrorResponse(xhr){

        let resp = null;
    
        try{
            resp = xhr.responseJSON ||
                   JSON.parse(xhr.responseText);
        }
        catch(e){
            // Non-JSON response
        }
    
        /*
         * ==================================================
         * FRAMEWORK STATES
         * ==================================================
         */
    
        if(
            xhr.status === 503 &&
            resp?.error === 'MAINTENANCE_MODE'
        ){
    
            hooks?.run?.(
                'callbora.maintenance',
                resp
            );
    
            return {
                handled: true,
                type: 'maintenance',
                response: resp,
                status: xhr.status
            };
        }
    
        /*
         * Security violation
         */
        if(
            xhr.status === 403 &&
            resp?.error === 'SECURITY_VIOLATION'
        ){
    
            hooks?.run?.(
                'callbora.securityViolation',
                resp
            );
    
            return {
                handled: true,
                type: 'security',
                response: resp,
                status: xhr.status
            };
        }
    
        /*
         * Authentication
         */
        if(
            xhr.status === 401
        ){
    
            hooks?.run?.(
                'callbora.unauthenticated',
                resp
            );
    
            return {
                handled: true,
                type: 'unauthenticated',
                response: resp,
                status: xhr.status
            };
        }
    
        /*
         * Rate limiting
         */
        if(
            xhr.status === 429
        ){
    
            hooks?.run?.(
                'callbora.rateLimited',
                resp
            );
    
            return {
                handled: true,
                type: 'rate_limited',
                response: resp,
                status: xhr.status
            };
        }
    
        /*
         * Domain/application error
         */
        if(
            xhr.status >= 400 &&
            xhr.status < 500 &&
            resp?.success === false &&
            resp?.code
        ){
    
            return {
                handled: true,
                type: 'domain',
                response: resp,
                status: xhr.status
            };
        }
    
        /*
         * Everything else is a system error.
         */
        return {
            handled: false,
            type: 'system',
            response: resp,
            status: xhr.status,
            xhr
        };
    }

    /* ==================================================
       CORE REQUEST ENGINE (Promise-Based)
    ================================================== */

    function request({
        url,
        method = 'POST',
        data = {},
        headers = {},
        responseType = null,
        download = false,
        filename = null,
        isUserInteraction = true
    }){

        return new Promise((resolve, reject)=>{

            if(isUserInteraction){
                headers["X-User-Interaction"] = "true";
            }

            const isFormData = data instanceof FormData;

            $.ajax({

                type: method,
                url,
                data,

                processData: !isFormData,
                contentType: isFormData
                    ? false
                    : 'application/x-www-form-urlencoded; charset=UTF-8',

                headers,

                xhrFields: {
                    withCredentials: true,
                    responseType: responseType || ""
                },

                success: (resp, status, xhr)=>{

                    if(download){

                        let blob = resp;

                        if(!(blob instanceof Blob)){
                            blob = new Blob([resp], {
                                type: xhr.getResponseHeader("Content-Type")
                            });
                        }

                        const objUrl = URL.createObjectURL(blob);
                        const a = document.createElement("a");

                        let name = filename;

                        const disposition =
                            xhr.getResponseHeader("Content-Disposition");

                        if(!name && disposition?.includes("filename=")){
                            name = disposition
                                .split("filename=")[1]
                                .replace(/"/g,"");
                        }

                        a.href = objUrl;
                        a.download = name || "download";
                        document.body.appendChild(a);
                        a.click();
                        a.remove();

                        URL.revokeObjectURL(objUrl);

                        resolve({ success:true, downloaded:true });
                        return;
                    }

                    resolve(resp);
                },

                error: (xhr)=>{

                    const result = resolveErrorResponse(xhr);
                
                    /*
                     * Expected application/framework state.
                     *
                     * Return it through the Promise rather than treating
                     * it as a transport/system failure.
                     */
                    if(result.handled){
                
                        resolve({
                            success: false,
                
                            error: result.response?.error
                                || result.response?.code
                                || result.type,
                
                            message: result.response?.message
                                || 'Request could not be completed.',
                
                            status: result.status,
                
                            state: result.type,
                
                            response: result.response
                        });
                
                        return;
                    }
                
                    /*
                     * Genuine infrastructure/system failure.
                     */
                    reject({
                        system: true,
                        type: result.type,
                        status: result.status,
                        response: result.response,
                        xhr
                    });
                }

                // error: (xhr)=>{

                //     let resp = null;

                //     try{
                //         resp = xhr.responseJSON ||
                //                JSON.parse(xhr.responseText);
                //     }catch(e){}

                //     // Domain error (expected)
                //     if(
                //         xhr.status >= 400 &&
                //         xhr.status < 500 &&
                //         resp?.success === false &&
                //         resp?.code
                //     ){
                //         resolve(resp);
                //         return;
                //     }

                //     // System error
                //     reject({
                //         system:true,
                //         xhr
                //     });
                // }
            });
        });
    }

    /* ==================================================
       HIGH-LEVEL HELPERS
    ================================================== */

    function get(url, data = {}, options = {}){
        return request({
            url,
            method:'GET',
            data,
            ...options
        });
    }

    function post(url, data = {}, options = {}){
        return request({
            url,
            method:'POST',
            data,
            ...options
        });
    }

    function download(url, options = {}){
        return request({
            url,
            method:'GET',
            download:true,
            responseType:'blob',
            ...options
        });
    }

    /* ==================================================
       LEGACY BUILDER COMPATIBILITY
    ================================================== */

    class CallBoraBuilder{

        constructor(url){
            this.opts = {
                url,
                method:'POST',
                data:{},
                headers:{}
            };
            this._callback = null;
            this._done     = null;
            this._error    = null;
        }

        setMethod(m){ this.opts.method = m; return this; }
        setParams(p){ this.opts.data = p; return this; }
        setHeaders(h){ Object.assign(this.opts.headers, h); return this; }
        setResponseType(t){ this.opts.responseType = t; return this; }
        setDownload(filename){
            this.opts.download = true;
            this.opts.filename = filename;
            this.opts.responseType = 'blob';
            return this;
        }

        setCallback(cb){ this._callback = cb; return this; }
        setDone(cb){ this._done = cb; return this; }
        setError(cb){ this._error = cb; return this; }

        build(){

            request(this.opts)
                .then(resp=>{
                    this._callback?.(resp);
                })
                .catch(err=>{
                    if(this._error){
                        this._error(err);
                    }
                    else{
                        logger?.error?.('System error', err);
                    }
                })
                .finally(()=>{
                    this._done?.();
                });
        }
    }

    /* ==================================================
       PUBLIC SERVICE API
    ================================================== */

    return {

        request,
        get,
        post,
        download,

        // Backward compatibility
        builder: (url)=> new CallBoraBuilder(url)
    };
});