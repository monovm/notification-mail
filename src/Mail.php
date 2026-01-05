<?php

namespace AbuseIO\Notification;

use AbuseIO\Models\Account;
use AbuseIO\Models\Brand;
use Marknl\Iodef;
use Config;
use Symfony\Component\Mailer\Mailer;
use Symfony\Component\Mailer\Transport;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Crypto\SMimeSigner;
use Illuminate\Support\Facades\Blade;
use URL;
use Log;

/**
 * Class Mail
 * @package AbuseIO\Notification
 */
class Mail extends Notification
{
    /**
     * @var Iodef\Elements\IODEFDocument
     */
    private $iodefDocument;

    /**
     * Create a new Notification instance
     */
    public function __construct()
    {
        parent::__construct($this);

        $this->iodefDocument = new Iodef\Elements\IODEFDocument();
    }

    /**
     * Sends out mail notifications for a specific $customerReference
     *
     * @param array $notifications
     * @return boolean Returns if succeeded or not
     */
    public function send($notifications)
    {
        $anonymize_domain = env('GDPR_ANONYMIZE_DOMAIN', 'example.com');
        foreach ($notifications as $customerReference => $notificationTypes) {

            $mails    = [];
            $tickets  = [];
            $accounts = [];

            foreach ($notificationTypes as $notificationType => $tickets) {

                foreach ($tickets as $ticket) {
                    $token['ip']     = $ticket->ash_token_ip;
                    $token['domain'] = $ticket->ash_token_domain;
                    $ashUrl          = config('main.ash.url') . 'collect/' . $ticket->id . '/';

                    $this->addIodefObject($ticket, $token[$notificationType], $ashUrl);

                    $box = [
                        'ticket_notification_type' => $notificationType,
                        'ip_contact_ash_link'      => $ashUrl . $token['ip'],
                        'domain_contact_ash_link'  => $ashUrl . $token['domain'],
                        'ticket_number'            => $ticket->id,
                        'ticket_ip'                => $ticket->ip,
                        'ticket_domain'            => $ticket->domain,
                        'ticket_type_name'         => trans("types.type.{$ticket->type_id}.name"),
                        'ticket_type_description'  => trans("types.type.{$ticket->type_id}.description"),
                        'ticket_class_name'        => trans("classifications.{$ticket->class_id}.name"),
                        'ticket_event_count'       => $ticket->events->count(),
                    ];

                    /*
                     * Even that all these tickets relate to the same customer reference, the contacts might be
                     * changed (added addresses, etc) for a specific ticket. To make sure people only get their own
                     * notificiations we aggregate them here before sending.
                     */
                    if ($notificationType == 'ip') {
                        $recipient            = $ticket->ip_contact_email;
                        $mails[$recipient][]  = $box;
                        $accounts[$recipient] = Account::find($ticket->ip_contact_account_id);
                    }

                    if ($notificationType == 'domain') {
                        $recipient            = $ticket->domain_contact_email;
                        $mails[$recipient][]  = $box;
                        $accounts[$recipient] = Account::find($ticket->domain_contact_account_id);
                    }
                }
            }

            foreach ($mails as $recipient => $boxes) {

                if (!empty($boxes)) {
                    
                    // create a new message (Symfony Email)
                    $email = new Email();

                    // create the src url for the active brand logo
                    if (!empty($accounts[$recipient]))
                    {
                        $account = $accounts[$recipient];
                    } else {
                        $account = Account::getSystemAccount();
                    }
                    $logo_url = URL::to('/ash/logo/' . $account->brand_id);
                    $brand = $account->brand;

                    $replacements = [
                        'boxes'        => $boxes,
                        'ticket_count' => count($tickets),
                        'logo_src'     => $logo_url,
                    ];

                    $subject   = config("{$this->configBase}.templates.subject");
                    $htmlmail  = config("{$this->configBase}.templates.html_mail");
                    $plainmail = config("{$this->configBase}.templates.plain_mail");

                    // render the default templates using Blade::render on strings
                    if(!empty($htmlmail)) {
                        try {
                            $htmlmail  = Blade::render($htmlmail, $replacements);
                        } catch (\Throwable $e) {
                            Log::warning("Incorrect template, it does not exist: " . $e->getMessage());
                        }
                    } else {
                        Log::warning("Incorrect template, it does not exist");
                    }

                    if(!empty($plainmail)) {
                        try {
                            $plainmail = Blade::render($plainmail, $replacements);
                        } catch (\Throwable $e) {
                            Log::warning("Incorrect template, it does not exist: " . $e->getMessage());
                        }
                    } else {
                        Log::warning("Incorrect template, it does not exist");
                    }

                    // if the current brand has custom mail template, use them
                    if ($brand->mail_custom_template) {
                        // defensive programming, doubble check the templates
                        $validator = \Validator::make(
                            [
                                'html'  => $brand->mail_template_html,
                                'plain' => $brand->mail_template_plain,
                            ],
                            [
                                'html'  => 'required|bladetemplate',
                                'plain' => 'required|bladetemplate',
                            ]);

                        if ($validator->passes()) {
                            try {
                                // only use the templates if they pass the validation
                                $htmloutput  = Blade::render($brand->mail_template_html, $replacements);
                                $plainoutput = Blade::render($brand->mail_template_plain, $replacements);

                                // no errors occurred while rendering
                                $htmlmail = $htmloutput;
                                $plainmail = $plainoutput;
                            } catch (\ErrorException $e) {
                                Log::warning("Incorrect template, falling back to default: " . $e->getMessage());
                            }
                        }
                    }

                    $iodef = new Iodef\Writer();
                    $iodef->formatOutput = true;
                    $iodef->write(
                        [
                            [
                                'name'       => 'IODEF-Document',
                                'attributes' => $this->iodefDocument->getAttributes(),
                                'value'      => $this->iodefDocument,
                            ]
                        ]
                    );
                    $XmlAttachmentData = $iodef->outputMemory();

                    // From, To, Bcc, Subject
                    $email->from(new Address(Config::get('main.notifications.from_address'), Config::get('main.notifications.from_name')));

                    if (!empty(Config::get('mail.override_address'))) {
                        $email->to(Config::get('mail.override_address'));
                    } else {
                        $email->to(...explode(',', $recipient));
                    }

                    if (!empty(Config::get('main.notifications.bcc_enabled'))) {
                        $email->bcc(Config::get('main.notifications.bcc_address'));
                    }

                    $email->priority(Email::PRIORITY_HIGHEST);
                    $email->subject($subject);

                    // Body composition
                    if(config("{$this->configBase}.notification.prefer_html_body")) {
                        $email->html($htmlmail);

                        if(config("{$this->configBase}.notification.text_part_enabled")) {
                            $email->text($plainmail);
                        }
                    } else {
                        $email->text($plainmail);

                        if(config("{$this->configBase}.notification.html_part_enabled")) {
                            $email->html($htmlmail);
                        }
                    }

                    // Attach gzipped IODEF XML
                    $email->attach(gzencode($XmlAttachmentData), 'iodef.xml.gz', 'application/gzip');

                    // Prepare Symfony Mailer transport from Laravel mail config
                    $defaultMailer = Config::get('mail.default', 'smtp');
                    $mailerCfg = Config::get("mail.mailers.$defaultMailer", []);

                    // If using an aggregate transport, choose the first concrete mailer
                    $transportName = $mailerCfg['transport'] ?? 'smtp';
                    if (in_array($transportName, ['failover', 'roundrobin'])) {
                        $first = $mailerCfg['mailers'][0] ?? 'smtp';
                        $mailerCfg = Config::get("mail.mailers.$first", []);
                        $transportName = $mailerCfg['transport'] ?? 'smtp';
                    }

                    $dsn = null;
                    if (!empty($mailerCfg['url'])) {
                        $dsn = $mailerCfg['url'];
                    } else {
                        switch ($transportName) {
                            case 'smtp':
                                $scheme = $mailerCfg['scheme'] ?? ((($mailerCfg['encryption'] ?? null) === 'ssl') ? 'smtps' : 'smtp');
                                $host = $mailerCfg['host'] ?? '127.0.0.1';
                                $port = $mailerCfg['port'] ?? 25;
                                $auth = '';
                                if (!empty($mailerCfg['username'])) {
                                    $auth = rawurlencode($mailerCfg['username']);
                                    if (!empty($mailerCfg['password'])) {
                                        $auth .= ':' . rawurlencode($mailerCfg['password']);
                                    }
                                    $auth .= '@';
                                }
                                $dsn = sprintf('%s://%s%s:%s', $scheme, $auth, $host, $port);
                                if (!empty($mailerCfg['encryption']) && $mailerCfg['encryption'] === 'tls') {
                                    $dsn .= '?encryption=tls';
                                }
                                break;
                            case 'sendmail':
                                $path = $mailerCfg['path'] ?? '/usr/sbin/sendmail -bs -i';
                                $dsn = 'sendmail://default?command=' . rawurlencode($path);
                                break;
                            case 'log':
                            case 'array':
                                // Use Symfony's Null transport equivalent
                                $dsn = 'null://null';
                                break;
                            default:
                                // Fallback to SMTP with minimal sane defaults
                                $scheme = 'smtp';
                                $host = $mailerCfg['host'] ?? '127.0.0.1';
                                $port = $mailerCfg['port'] ?? 25;
                                $dsn = sprintf('%s://%s:%s', $scheme, $host, $port);
                                break;
                        }
                    }

                    try {
                        $transport = Transport::fromDsn($dsn);
                    } catch (\Throwable $e) {
                        // As a safety net, fall back to null transport to avoid fatal DSN errors in dev
                        Log::warning('Invalid mailer DSN ("'.$dsn.'"). Falling back to null transport: '.$e->getMessage());
                        $transport = Transport::fromDsn('null://null');
                    }
                    $mailer = new Mailer($transport);

                    // S/MIME signing if configured
                    $signedMessage = null;
                    if (!empty(Config::get('mail.smime.enabled')) &&
                        (Config::get('mail.smime.enabled')) === true &&
                        !empty(Config::get('mail.smime.certificate')) &&
                        !empty(Config::get('mail.smime.key')) &&
                        is_file(Config::get('mail.smime.certificate')) &&
                        is_file(Config::get('mail.smime.key'))
                    ) {
                        try {
                            $smimeSigner = new SMimeSigner(
                                Config::get('mail.smime.certificate'),
                                Config::get('mail.smime.key')
                            );
                            $signedMessage = $smimeSigner->sign($email);
                        } catch (\Throwable $e) {
                            Log::warning('S/MIME signing failed: ' . $e->getMessage());
                        }
                    }

                    // only really send if the email address isn't anonymized
                    $regexp = '/@'.$anonymize_domain.'$/';
                    if (preg_match($regexp, $recipient) !== 1) {
                        try {
                            $mailer->send($signedMessage ?: $email);
                        } catch (\Throwable $e) {
                            return $this->failed("Error while sending message to {$recipient}: " . $e->getMessage());
                        }
                    }
                }
            }

        }

        return $this->success();
    }

    /**
     * Adds IOdef data from this ticket to the document
     *
     * @param object $ticket Ticket model
     * @param string $token ASH token
     * @param string $ashUrl ASH Url
     */
    private function addIodefObject($ticket, $token, $ashUrl)
    {
        // Add report type, origin and date
        $incident = new Iodef\Elements\Incident();
        $incident->setAttributes(
            [
                'purpose' => 'reporting'
            ]
        );

        // Add ASH Link
        $ashlink = new Iodef\Elements\AdditionalData;
        $ashlink->setAttributes(
            [
                'dtype'       => 'string',
                'meaning'     => 'ASH Link',
                'restriction' => 'private',
            ]
        );
        $ashlink->value = !empty($token) ? ($ashUrl . $token) : $ashUrl;
        $incident->addChild($ashlink);

        // Add ASH Token seperatly
        if (!empty($token)) {
            $ashtoken = new Iodef\Elements\AdditionalData;
            $ashtoken->setAttributes(
                [
                    'dtype'       => 'string',
                    'meaning'     => 'ASH Token',
                    'restriction' => 'private',
                ]
            );
            $ashtoken->value = $token;
            $incident->addChild($ashtoken);
        }

        // Add AbuseDesk Status seperatly
        $ticketStatus = new Iodef\Elements\AdditionalData;
        $ticketStatus->setAttributes(
            [
                'dtype'       => 'string',
                'meaning'     => 'Ticket status',
                'restriction' => 'private',
            ]
        );

        $ticketStatus->value = $ticket->status_id;
        $incident->addChild($ticketStatus);

        // Add Contact Status seperatly
        $contactStatus = new Iodef\Elements\AdditionalData;
        $contactStatus->setAttributes(
            [
                'dtype'       => 'string',
                'meaning'     => 'Contact status',
                'restriction' => 'private',
            ]
        );
        $contactStatus->value = $ticket->contact_status_id;
        $incident->addChild($contactStatus);

        // Add SourceID seperatly
        $sourceID = new Iodef\Elements\AdditionalData;
        $sourceID->setAttributes(
            [
                'dtype'       => 'string',
                'meaning'     => 'SourceID',
                'restriction' => 'private',
            ]
        );
        $sourceID->value = config('app.id');
        $incident->addChild($sourceID);

        // Add Incident data
        $incidentID = new Iodef\Elements\IncidentID();
        $incidentID->setAttributes(
            [
                'name'        => 'https://myhost.isp.local/api/',
                'restriction' => 'need-to-know',
            ]
        );
        $incidentID->value($ticket->id);
        $incident->addChild($incidentID);

        $reportTime = new Iodef\Elements\ReportTime();
        $reportTime->value(date('Y-m-d\TH:i:sP'));
        $incident->addChild($reportTime);

        // Add ticket abuse classification and type
        $assessment = new Iodef\Elements\Assessment();
        $impact = new Iodef\Elements\Impact();
        $severity = [
            'INFO'       => 'low',
            'ABUSE'      => 'medium',
            'ESCALATION' => 'high',
        ];
        $impact->setAttributes(
            [
                'type'     => 'ext-value',
                'ext-type' => $ticket->class_id,
                'severity' => $severity[$ticket->type_id] ?? 'low',
            ]
        );
        $assessment->addChild($impact);
        $incident->addChild($assessment);

        // Add Origin/Creator contact information for this ticket
        $contact = new Iodef\Elements\Contact();
        $contact->setAttributes(
            [
                'role'        => 'creator',
                'type'        => 'ext-value',
                'ext-type'    => 'Software',
                'restriction' => 'need-to-know',
            ]
        );

        $contactName = new Iodef\Elements\ContactName();
        $contactName->value('AbuseIO downstream provider');
        $contact->addChild($contactName);

        $email = new Iodef\Elements\Email();
        $email->value('notifier@abuse.io');
        $contact->addChild($email);

        $incident->addChild($contact);

        // Add Abusedesk contact information for this ticket
        $contact = new Iodef\Elements\Contact();
        $contact->setAttributes(
            [
                'role'        => 'irt',
                'type'        => 'organization',
                'restriction' => 'need-to-know',
            ]
        );

        $contactName = new Iodef\Elements\ContactName();
        $contactName->value(config('main.notifications.from_name'));
        $contact->addChild($contactName);

        $email = new Iodef\Elements\Email();
        $email->value(config('main.notifications.from_address'));
        $contact->addChild($email);

        $incident->addChild($contact);

        // Add ticket events as records
        if ($ticket->events->count() >= 1) {
            foreach ($ticket->events as $event) {
                $eventData = new Iodef\Elements\EventData();

                // Add the IP and Domain data to each record
                $flow = new Iodef\Elements\Flow;

                $system = new Iodef\Elements\System;
                $system->setAttributes(
                    [
                        'category' => 'source',
                        'spoofed'  => 'no'
                    ]
                );

                $node = new Iodef\Elements\Node;

                if (!empty($ticket->ip)) {
                    $address = new Iodef\Elements\Address;
                    $category = [];
                    if (filter_var($ticket->ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                        $category['category'] = 'ipv4-addr';
                    } elseif (filter_var($ticket->ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                        $category['category'] = 'ipv6-addr';
                    } else {
                        $category['category']     = 'ext-value';
                        $category['ext-category'] = 'unknown';

                    }

                    $address->setAttributes($category);
                    $address->value = $ticket->ip;

                    $node->addChild($address);

                }

                if (!empty($ticket->domain)) {
                    $domain = new Iodef\Elements\NodeName;
                    $domain->value = $ticket->domain;

                    $node->addChild($domain);
                }

                $system->addChild($node);
                $flow->addChild($system);
                $eventData->addChild($flow);


                // Now actually add event data
                $record = new Iodef\Elements\Record;
                $record->setAttributes(['restriction' => 'need-to-know']);

                $recordData = new Iodef\Elements\RecordData;

                $recordDateTime = new Iodef\Elements\DateTime;
                $recordDateTime->value = date('Y-m-d\TH:i:sP', $event->timestamp);
                $recordData->addChild($recordDateTime);

                $recordDescription = new Iodef\Elements\Description;
                $recordDescription->value = "Source:{$event->source}";
                $recordData->addChild($recordDescription);

                $recordItem = new Iodef\Elements\RecordItem;
                $recordItem->setAttributes(
                    [
                        'dtype'     => 'ext-value',
                        'ext-dtype' => 'json',
                    ]
                );
                $recordItem->value = $event->information;
                $recordData->addChild($recordItem);

                $record->addChild($recordData);

                $eventData->addChild($record);

                $incident->addChild($eventData);
            }
        }

        // Add ticket notes as history items
        if ($ticket->notes->count() >= 1) {
            $history = new Iodef\Elements\History;

            $elementCounter = 0;
            foreach ($ticket->notes as $note) {
                if ($note->hidden == true) {
                    continue;
                }

                $historyItem = new Iodef\Elements\HistoryItem;
                $historyItem->setAttributes(
                    [
                        'action'      => 'status-new-info',
                        'restriction' => 'need-to-know'
                    ]
                );

                $historyDateTime = new Iodef\Elements\DateTime;
                $historyDateTime->value = date('Y-m-d\TH:i:sP', strtotime($note->created_at));
                $historyItem->addChild($historyDateTime);

                $historySubmitter = new Iodef\Elements\AdditionalData;
                $historySubmitter->setAttributes(
                    [
                        'meaning' => 'submitter',
                    ]
                );
                $historySubmitter->value = "{$note->submitter}";
                $historyItem->addChild($historySubmitter);

                // Add note text only when present to satisfy 'value' requirement
                if (!empty(trim($note->text))) {
                    $historyNote = new Iodef\Elements\AdditionalData;
                    $historyNote->setAttributes(
                        [
                            'dtype'    => 'string',
                            'meaning'  => 'text',
                        ]
                    );
                    $historyNote->value = "{$note->text}";
                    $historyItem->addChild($historyNote);
                }

                $history->addChild($historyItem);
                $elementCounter++;
            }

            if($elementCounter >= 1) {
                $incident->addChild($history);
            }
        }

        // Add incident to the document
        $this->iodefDocument->addChild($incident);
    }
}
