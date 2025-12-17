class CallBora {
    constructor(url) {
        this.url = url;
        this.m = "POST";      // default method
        this.d = "json";      // default datatype
        this.params = {};
        this.headers = {};
        this.callback = null;
        this.ondone = null;
        this.onerror = null;
        this.credentials = null; // optional { user, pass }
        this.downloadEnabled = false;
        this.downloadFilename = null;
        this.responseType = null; // null = default jQuery json
    }

    setMethod(method) {
        this.m = method.toUpperCase();
        return this;
    }

    setDataType(type) {
        this.d = type;
        return this;
    }

    setParams(params) {
        this.params = params;
        return this;
    }

    setHeaders(headers) {
        Object.assign(this.headers, headers);
        return this;
    }

    setCredentials(user, pass) {
        this.credentials = { user, pass };
        return this;
    }

    setCallback(callback) {
        this.callback = callback;
        return this;
    }

    setDone(done) {
        this.ondone = done;
        return this;
    }

    setError(error) {
        this.onerror = error;
        return this;
    }

    setDownload(filename = null) {
        this.downloadEnabled = true;
        this.downloadFilename = filename; // can be null → server filename used
        this.responseType = "blob"; // force blob for downloads
        this.d = ""; // jQuery should NOT parse the response
        return this;
    }

    setResponseType(type) {
        this.responseType = type; // "blob", "arraybuffer", etc.
        if (type === "blob") this.d = "";
        return this;
    }

	prepareUrl(url, prefix){
		return url.startsWith("http://") || url.startsWith("https://") ? url : prefix + url;
	}

    ajx(isUserInteraction = true) {
        if (isUserInteraction) {
            this.headers["X-User-Interaction"] = "true";
        }

        $.ajax({
            type: this.m,
            url: this.prepareUrl(this.url, ''),
            data: this.params,
            headers: this.headers,
            xhrFields: { 
                withCredentials: true,
                responseType: this.responseType || undefined
            },
            beforeSend: (xhr) => {
                if (this.credentials) {
                    xhr.setRequestHeader(
                        "Authorization",
                        "Basic " + btoa(this.credentials.user + ":" + this.credentials.pass)
                    );
                }
            },
            dataType: this.d,
            success: (data, status, xhr) => {
                // Handle automatic download
                if (this.downloadEnabled) {

                    let blob = data;
                    // If jQuery didn’t automatically give blob
                    if (!(blob instanceof Blob)) {
                        blob = new Blob([data], { type: xhr.getResponseHeader("Content-Type") });
                    }

                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    // If filename not provided, use Content-Disposition header
                    let filename = this.downloadFilename;
                    const disposition = xhr.getResponseHeader("Content-Disposition");
                    if (!filename && disposition && disposition.indexOf("filename=") !== -1) {
                        filename = disposition.split("filename=")[1].replace(/"/g, "");
                    }
                    a.download = filename || "download";
                    document.body.appendChild(a);
                    a.click();
                    a.remove();

                    window.URL.revokeObjectURL(url);

                    if (typeof this.callback === "function") {
                        this.callback({ success: true, downloaded: true });
                    }

                    return;
                }
                if (typeof this.callback === "function") this.callback(data);
            },
            complete: () => {
                if (typeof this.ondone === "function") this.ondone();
            },
            error: (xhr, textStatus, errorThrown) => {
                if (typeof this.onerror === "function") {
                    this.onerror(xhr, textStatus, errorThrown);
                } else {
                    console.warn("AJAX error:", textStatus, errorThrown);
                }
            }
        });
    }

    build() {
		// alert('build');
		this.ajx(true);
        // getNs("EInit", () => this.ajx(true));
    }
}

// new CallBora("/api/save")
//     .setMethod("POST")
//     .setParams({ id: 1, name: "Fiki" })
//     .setCallback((res) => console.log("Success:", res))
//     .setDone(() => console.log("Request finished"))
//     .setError((xhr) => console.error("Error:", xhr))
//     .build();

