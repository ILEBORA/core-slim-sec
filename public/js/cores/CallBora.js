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
            xhrFields: { withCredentials: true },
            beforeSend: (xhr) => {
                if (this.credentials) {
                    xhr.setRequestHeader(
                        "Authorization",
                        "Basic " + btoa(this.credentials.user + ":" + this.credentials.pass)
                    );
                }
            },
            dataType: this.d,
            success: (data) => {
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

